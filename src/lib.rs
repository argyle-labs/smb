//! SMB / CIFS integration. A *thin* domain adapter: it owns only what is
//! SMB-specific — mounting (`mount.cifs` on Linux, `mount_smbfs` on macOS),
//! server share discovery (`smbclient -L`), credentials, and unmount — and
//! reaches everything generic (the cross-platform kernel mount table, mount
//! health classification) through the shared `plugin_toolkit::storage`
//! primitives. There is no SMB-specific `/proc/mounts` parser or `Mount`/`Health`
//! type here anymore; those are the storage domain's job.
//!
//! This module shells out — there is no quality cross-platform Rust SMB
//! client crate that handles the kernel-mount and userspace-share-listing
//! cases together. Shelling out also means the user's existing kerberos
//! / smb.conf / cifs creds files keep working.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use plugin_toolkit::async_trait;
use plugin_toolkit::path::which;
use plugin_toolkit::prelude::*;
use plugin_toolkit::storage::{
    mount_table_of, probe_health, Capability, Health, MountEntry, MountOutcome,
    Share as StorageShare, StorageBackend, StorageError, StorageKind,
};
use plugin_toolkit::tokio::process::Command;

mod abi_export;

/// Filesystem types that denote an SMB/CIFS mount in the kernel mount table.
/// This is the one piece of SMB-domain knowledge the generic mount-table
/// primitive needs from us.
pub const SMB_FSTYPES: &[&str] = &["cifs", "smb3", "smbfs"];

#[derive(Debug)]
pub enum SmbError {
    MissingTool(&'static str),
    ToolFailed {
        tool: &'static str,
        code: Option<i32>,
        stderr: String,
    },
    Io(std::io::Error),
    Timeout(Duration),
    Unsupported,
}

impl std::fmt::Display for SmbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmbError::MissingTool(tool) => write!(f, "required tool not found on PATH: {tool}"),
            SmbError::ToolFailed { tool, code, stderr } => {
                write!(f, "smb tool failed: {tool} (exit {code:?}): {stderr}")
            }
            SmbError::Io(e) => write!(f, "io: {e}"),
            SmbError::Timeout(d) => write!(f, "operation timed out after {d:?}"),
            SmbError::Unsupported => write!(f, "unsupported on this platform"),
        }
    }
}

impl std::error::Error for SmbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SmbError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SmbError {
    fn from(e: std::io::Error) -> Self {
        SmbError::Io(e)
    }
}

/// One share advertised by a server.
#[plugin_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub name: String,
    pub kind: ShareKind,
    pub comment: String,
}

#[plugin_struct]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShareKind {
    Disk,
    Ipc,
    Printer,
    Other,
}

/// Credentials for [`mount`]. Either a creds-file path (with `username=` and
/// `password=` lines, as cifs.upcall expects) or inline username+password.
#[derive(Debug, Clone)]
pub enum Credentials {
    File(PathBuf),
    Inline { username: String, password: String },
    Guest,
}

#[derive(Debug, Clone)]
pub struct MountSpec<'a> {
    pub server: &'a str,
    pub share: &'a str,
    pub mountpoint: &'a Path,
    pub credentials: Credentials,
    /// Extra CIFS options passed via `-o`. Typical: `vers=3.0`, `iocharset=utf8`,
    /// `uid=1000`, `noperm`. Server/share/creds are inserted alongside.
    pub extra_opts: Vec<String>,
}

/// Currently-mounted SMB/CIFS shares, read from the shared cross-platform
/// mount-table primitive and filtered to SMB filesystem types. No SMB-specific
/// parsing lives here — that is the storage domain's `mount_table`.
pub fn list_mounts() -> Result<Vec<MountEntry>, SmbError> {
    mount_table_of(SMB_FSTYPES).map_err(SmbError::Io)
}

/// Time-bounded health probe of a mountpoint, delegating to the shared
/// primitive so nfs and smb classify liveness identically.
pub fn health(mountpoint: &Path, probe_timeout: Duration) -> Health {
    probe_health(&mountpoint.to_string_lossy(), probe_timeout)
}

/// Mount an SMB share. Linux uses `mount.cifs`; macOS uses `mount_smbfs`.
/// Caller must have permission to mount (typically root on Linux, current
/// user on macOS).
pub async fn mount(spec: MountSpec<'_>) -> Result<(), SmbError> {
    #[cfg(target_os = "linux")]
    {
        which("mount.cifs").ok_or(SmbError::MissingTool("mount.cifs"))?;
        let mut opts: Vec<String> = Vec::new();
        match &spec.credentials {
            Credentials::File(p) => opts.push(format!("credentials={}", p.display())),
            Credentials::Inline { username, password } => {
                opts.push(format!("username={username}"));
                opts.push(format!("password={password}"));
            }
            Credentials::Guest => opts.push("guest".to_string()),
        }
        opts.extend(spec.extra_opts.iter().cloned());
        let source = format!("//{}/{}", spec.server, spec.share);
        run_tool(
            "mount.cifs",
            &[
                source.as_str(),
                spec.mountpoint.to_str().unwrap_or(""),
                "-o",
                opts.join(",").as_str(),
            ],
        )
        .await
    }
    #[cfg(target_os = "macos")]
    {
        which("mount_smbfs").ok_or(SmbError::MissingTool("mount_smbfs"))?;
        let auth_part = match &spec.credentials {
            Credentials::Inline { username, password } => {
                format!("{}:{}@", urlencode(username), urlencode(password))
            }
            Credentials::Guest => String::new(),
            Credentials::File(_) => String::new(), // macOS uses keychain; ignored.
        };
        let url = format!("//{}{}/{}", auth_part, spec.server, spec.share);
        run_tool(
            "mount_smbfs",
            &[url.as_str(), spec.mountpoint.to_str().unwrap_or("")],
        )
        .await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = spec;
        Err(SmbError::Unsupported)
    }
}

/// Unmount a previously-mounted share.
pub async fn unmount(mountpoint: &Path) -> Result<(), SmbError> {
    which("umount").ok_or(SmbError::MissingTool("umount"))?;
    run_tool("umount", &[mountpoint.to_str().unwrap_or("")]).await
}

/// List shares advertised by `server` via `smbclient -L //server`.
pub async fn list_shares(server: &str, credentials: &Credentials) -> Result<Vec<Share>, SmbError> {
    which("smbclient").ok_or(SmbError::MissingTool("smbclient"))?;
    let mut args: Vec<String> = vec![format!("-L"), format!("//{server}"), "-g".into()];
    match credentials {
        Credentials::Guest => args.push("-N".into()),
        Credentials::Inline { username, password } => {
            args.push("-U".into());
            args.push(format!("{username}%{password}"));
        }
        Credentials::File(p) => {
            args.push("-A".into());
            args.push(p.display().to_string());
        }
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("smbclient").args(&arg_refs).output().await?;
    if !output.status.success() {
        return Err(SmbError::ToolFailed {
            tool: "smbclient",
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(parse_smbclient_shares(
        std::str::from_utf8(&output.stdout).unwrap_or(""),
    ))
}

pub(crate) fn parse_smbclient_shares(raw: &str) -> Vec<Share> {
    // -g (grep-friendly) format: lines like
    //   Disk|public|Public files
    //   IPC|IPC$|IPC Service (Samba 4.x)
    raw.lines()
        .filter_map(|line| {
            let mut parts = line.split('|');
            let kind = parts.next()?;
            let name = parts.next()?;
            let comment = parts.next().unwrap_or("");
            let kind = match kind.trim() {
                "Disk" => ShareKind::Disk,
                "IPC" => ShareKind::Ipc,
                "Printer" => ShareKind::Printer,
                _ => return None,
            };
            Some(Share {
                name: name.to_string(),
                kind,
                comment: comment.to_string(),
            })
        })
        .collect()
}

async fn run_tool(tool: &'static str, args: &[&str]) -> Result<(), SmbError> {
    let out = Command::new(tool).args(args).output().await?;
    if out.status.success() {
        Ok(())
    } else {
        Err(SmbError::ToolFailed {
            tool,
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[cfg(target_os = "macos")]
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

// ── storage domain backend ──────────────────────────────────────────────────

/// SMB/CIFS network-share backend for the `storage` domain. Contributes the
/// host's live SMB/CIFS mounts as shares and exposes unmount. Mount, list of
/// server-advertised shares, and usage stay [`StorageError::Unsupported`] here:
/// the storage-domain `mount`/`list_shares` operations take a single id/target,
/// but driving an SMB mount needs a server + share + credentials ([`MountSpec`])
/// which this thin descriptor cannot supply.
pub struct SmbBackend {
    name: String,
}

impl SmbBackend {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for SmbBackend {
    fn default() -> Self {
        Self::new("smb")
    }
}

#[async_trait::async_trait]
impl StorageBackend for SmbBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> StorageKind {
        StorageKind::NetworkShare
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::List, Capability::Unmount]
    }

    fn endpoint(&self) -> String {
        "smb://local".to_string()
    }

    async fn list_shares(&self) -> Result<Vec<StorageShare>, StorageError> {
        let mounts = list_mounts().map_err(|e| StorageError::Transport(e.to_string()))?;
        Ok(mounts
            .into_iter()
            .map(|m| StorageShare {
                id: m.mountpoint.clone(),
                source: m.source,
                target: Some(m.mountpoint),
                fstype: m.fstype,
                mounted: true,
            })
            .collect())
    }

    async fn unmount(&self, target: &str) -> Result<MountOutcome, StorageError> {
        unmount(Path::new(target))
            .await
            .map_err(|e| StorageError::Other(format!("unmount {target}: {e}")))?;
        Ok(MountOutcome {
            target: target.to_string(),
            mounted: false,
            recovered: false,
            detail: None,
        })
    }
}

/// Register the smb storage backend with the process-global `storage` registry.
/// Retained for the `rlib` shape (in-process embedding / tests); the cdylib
/// plugin path contributes the backend via [`abi_export`]'s `backends()` seam
/// instead, so a `dlopen`ing orca never calls this.
pub fn bootstrap() {
    plugin_toolkit::storage::register_backend(Arc::new(SmbBackend::default()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json;

    #[test]
    fn parse_smbclient_shares_extracts_disk_and_ipc() {
        let raw = "\
Disk|public|Public files
Disk|backup|
IPC|IPC$|IPC Service
Printer|hpoffice|HP printer
something invalid
";
        let shares = parse_smbclient_shares(raw);
        assert_eq!(shares.len(), 4);
        assert_eq!(shares[0].kind, ShareKind::Disk);
        assert_eq!(shares[0].name, "public");
        assert_eq!(shares[2].kind, ShareKind::Ipc);
        assert_eq!(shares[3].kind, ShareKind::Printer);
    }

    #[test]
    fn parse_smbclient_shares_skips_unknown_kinds_and_short_lines() {
        let raw = "Disk|x|c\nUnknown|y|c\nDisk\n";
        let shares = parse_smbclient_shares(raw);
        // Only the well-formed Disk line maps; "Unknown" kind dropped;
        // "Disk" alone (no name field) dropped.
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "x");
    }

    #[test]
    fn list_mounts_filters_to_smb_fstypes() {
        // Delegates to the shared primitive; on any platform it must return Ok
        // and contain only SMB-family fstypes (usually empty on CI).
        let mounts = list_mounts().expect("mount table readable");
        assert!(mounts
            .iter()
            .all(|m| SMB_FSTYPES.contains(&m.fstype.as_str())));
    }

    #[tokio::test]
    async fn health_missing_when_path_absent() {
        let h = health(
            Path::new("/nonexistent_orca_smb_test"),
            Duration::from_secs(1),
        );
        assert_eq!(h, Health::Missing);
    }

    #[tokio::test]
    async fn health_ok_for_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        let h = health(dir.path(), Duration::from_secs(2));
        assert_eq!(h, Health::Ok);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn urlencode_passes_safe_chars_and_escapes_others() {
        assert_eq!(urlencode("abcXYZ012-_.~"), "abcXYZ012-_.~");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("p@ss/word"), "p%40ss%2Fword");
    }

    #[tokio::test]
    async fn unmount_invalid_path_returns_tool_failed() {
        // umount(1) is universally present on macOS/Linux; the failure path
        // surfaces ToolFailed. We don't assert exit code (varies by impl).
        let res = unmount(Path::new("/nonexistent_orca_smb_unmount_test")).await;
        match res {
            Err(SmbError::ToolFailed { tool, .. }) => assert_eq!(tool, "umount"),
            Err(SmbError::MissingTool(_)) => {} // also acceptable on minimal images
            other => panic!("expected ToolFailed or MissingTool, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_shares_propagates_smbclient_failure_or_missing() {
        // smbclient is usually absent on macOS CI images and the function
        // surfaces MissingTool. If the test host happens to have smbclient,
        // pointing it at a black-hole server will surface ToolFailed.
        let res = list_shares("127.0.0.1:1", &Credentials::Guest).await;
        assert!(matches!(
            res,
            Err(SmbError::MissingTool(_)) | Err(SmbError::ToolFailed { .. })
        ));
    }

    #[test]
    fn share_kind_round_trips_through_serde() {
        for k in [
            ShareKind::Disk,
            ShareKind::Ipc,
            ShareKind::Printer,
            ShareKind::Other,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let back: ShareKind = serde_json::from_str(&j).unwrap();
            assert_eq!(back, k);
        }
    }

    #[test]
    fn smb_error_display_covers_each_variant() {
        let e = SmbError::MissingTool("mount.cifs");
        assert!(e.to_string().contains("mount.cifs"));
        let e = SmbError::ToolFailed {
            tool: "x",
            code: Some(2),
            stderr: "boom".into(),
        };
        assert!(e.to_string().contains("boom"));
        let e = SmbError::Timeout(Duration::from_secs(3));
        assert!(e.to_string().contains("timed out"));
        let e = SmbError::Unsupported;
        assert!(e.to_string().contains("unsupported"));
        let io: SmbError = std::io::Error::other("x").into();
        assert!(io.to_string().starts_with("io:"));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn mount_macos_with_inline_creds_runs_through_to_tool() {
        // mount_smbfs exists on macOS; pointing at a black-hole server
        // forces it to exit non-zero so we exercise the
        // run_tool/ToolFailed branch. If the binary somehow isn't on PATH,
        // MissingTool is also acceptable.
        let dir = tempfile::tempdir().unwrap();
        let spec = MountSpec {
            server: "127.0.0.1:1",
            share: "nope",
            mountpoint: dir.path(),
            credentials: Credentials::Inline {
                username: "u".into(),
                password: "p".into(),
            },
            extra_opts: vec![],
        };
        let res = mount(spec).await;
        assert!(matches!(
            res,
            Err(SmbError::ToolFailed { .. }) | Err(SmbError::MissingTool(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn list_mounts_macos_returns_a_vec() {
        // /sbin/mount is always present on macOS; assert the call returns Ok.
        let mounts = list_mounts().expect("/sbin/mount runs");
        let _ = mounts.len();
    }
}
