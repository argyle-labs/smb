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

use plugin_toolkit::orca_async;
use plugin_toolkit::path::which;
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::storage::{
    is_valid_secret_file_path, mount_table_of, parse_option_string, probe_health, secret_file_path,
    Capability, Health, MountEntry, MountOutcome, MountSpec as StorageMountSpec, MountStyle,
    NormalizedSpec, OptionBuilder, OptionSet, RecoverOutcome, SecretFile, SecretRef,
    Share as StorageShare, StorageBackend, StorageError, StorageKind,
};

/// Filesystem types that denote an SMB/CIFS mount in the kernel mount table.
/// This is the one piece of SMB-domain knowledge the generic mount-table
/// primitive needs from us.
pub const SMB_FSTYPES: &[&str] = &["cifs", "smb3", "smbfs"];

/// SMB tool / transport errors. Expressed entirely through the orca-native
/// `#[orca_error]` abstraction — the plugin names no error crate; the macro
/// emits `Display` + `std::error::Error` (with the `Io` source chain) + the
/// `From<std::io::Error>` conversion.
#[orca_error]
pub enum SmbError {
    #[orca(display = "required tool not found on PATH: {0}")]
    MissingTool(&'static str),
    #[orca(display = "smb tool failed: {tool} (exit {code:?}): {stderr}")]
    ToolFailed {
        tool: &'static str,
        code: Option<i32>,
        stderr: String,
    },
    #[orca(display = "io: {0}", from)]
    Io(std::io::Error),
    #[orca(display = "operation timed out after {0:?}")]
    Timeout(Duration),
    #[orca(display = "unsupported on this platform")]
    Unsupported,
}

/// One share advertised by a server.
#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub name: String,
    pub kind: ShareKind,
    pub comment: String,
}

#[orca_struct]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[orca(rename_all = "lowercase")]
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
    let mut args: Vec<String> = vec!["-L".into(), format!("//{server}"), "-g".into()];
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
    if !output.status.success {
        return Err(SmbError::ToolFailed {
            tool: "smbclient",
            code: output.status.code,
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
    // Generic "shell out, fail on non-zero" mechanism (core); map its ToolError
    // into this plugin's own SmbError. `tool` stays a `&'static str` for the
    // error variant, so the ToolError's own tool string is discarded in favor of
    // it.
    Command::new(tool)
        .args(args)
        .run_checked()
        .await
        .map(|_stdout| ())
        .map_err(|e| SmbError::ToolFailed {
            tool,
            code: e.code,
            stderr: e.stderr,
        })
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

// ── smb/cifs option grammar (Phase 3) ────────────────────────────────────────
//
// This backend owns the grammar of its own mount options. `validate_spec` parses
// the store's raw comma-string into a local typed `SmbOptions`, rejecting malformed
// values at declare time, then hands core the rendered string as an opaque
// `OptionSet::Raw`; `render_options` reproduces the canonical cifs option string
// autofs consumes. Core never parses this grammar. The one non-negotiable property
// (see the credential note on `render_smb_options`): an inline
// username/password credential is NEVER rendered into the world-readable autofs
// map — the password is a `SecretRef` the secrets domain resolves, and inline
// credentials are referenced through a root-written `credentials=<path>` file.

/// SMB protocol versions this backend accepts for the `vers=` mount option.
/// mount.cifs accepts more (1.0, 2.0, 2.1, 3.0, 3.02, 3.1.1); we accept the
/// modern, safe set and reject anything else at declare time so a typo surfaces
/// before a mount is ever attempted.
pub const SMB_VERSIONS: &[&str] = &["2.0", "2.1", "3.0", "3.1.1"];

/// SMB/CIFS credential source. This backend owns the credential grammar: it
/// validates that exactly one coherent form is supplied, then renders it into the
/// cifs option string / creds-file. Local to the smb plugin — core is
/// fstype-agnostic and knows no credential grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmbCredentials {
    /// A `credentials=<path>` file holding username/password/domain.
    File { path: String },
    /// Inline username/password/domain, the password resolved via the secrets
    /// domain (a [`SecretRef`]).
    Inline {
        username: String,
        password: SecretRef,
        domain: Option<String>,
    },
    /// Guest / anonymous mount (`guest`).
    Guest,
}

/// Render the contents of a cifs creds-file from resolved inline credentials: the
/// exact `mount.cifs` `credentials=` file grammar — `username=`, `password=`, and
/// (when set) `domain=`, one per line. `password` is the **resolved plaintext**,
/// never a [`SecretRef`]; the caller resolves the ref first and hands the result
/// only to core's privileged 0600 writer via the generic `SecretFile` seam.
pub fn render_creds_file(username: &str, password: &str, domain: Option<&str>) -> String {
    let mut out = format!("username={username}\npassword={password}\n");
    if let Some(d) = domain {
        out.push_str(&format!("domain={d}\n"));
    }
    out
}

/// Parse + validate a declarative [`StorageMountSpec`] into a typed
/// [`SmbCredentials`]-carrying option set.
///
/// Grammar accepted in the raw option string:
///   * `vers=<v>`         — must be one of [`SMB_VERSIONS`]
///   * `credentials=<p>`  — a creds-file path (File credential form)
///   * `guest`            — anonymous mount (Guest credential form)
///   * `username=<u>`     — inline username (Inline form; password from `SecretRef`)
///   * `domain=<d>`       — inline domain (only valid alongside `username=`)
///   * `uid=<u>` / `gid=<g>` / `iocharset=<c>` — mapping options
///   * `noperm`           — client-side permission bypass flag
///   * anything else      — passthrough, preserved in `extra`
///
/// Credential source resolution + validation (exactly one coherent form):
///   * `credentials=<p>` present            → [`SmbCredentials::File`]
///   * `guest` present                      → [`SmbCredentials::Guest`]
///   * `username=` present + spec credential → [`SmbCredentials::Inline`]
///     (the `credential` field carries the password `SecretRef`)
///   * none of the above                    → default to Guest
///
/// Conflicting forms (e.g. `guest` + `credentials=`, or `username=` without a
/// password `SecretRef`, or `credentials=` + `username=`) are rejected with a
/// clear [`StorageError`].
/// The smb backend's local typed option model. Core never sees this — it holds
/// only the rendered `OptionSet::Raw` string plus the generic `SecretFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbOptions {
    pub vers: Option<String>,
    pub credentials: SmbCredentials,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub iocharset: Option<String>,
    pub noperm: bool,
    pub extra: Vec<String>,
}

pub fn validate_smb_options(spec: &StorageMountSpec) -> Result<SmbOptions, StorageError> {
    let raw = spec.options.as_deref().unwrap_or("");

    let mut vers: Option<String> = None;
    let mut creds_path: Option<String> = None;
    let mut guest = false;
    let mut username: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut uid: Option<String> = None;
    let mut gid: Option<String> = None;
    let mut iocharset: Option<String> = None;
    let mut noperm = false;
    let mut extra: Vec<String> = Vec::new();

    // Generic tokenizer (core mechanics); the SMB grammar below is all ours.
    for opt in parse_option_string(raw) {
        let (key, value) = (opt.key, opt.value.map(str::to_string));
        match (key, value) {
            ("vers", Some(v)) => {
                if !SMB_VERSIONS.contains(&v.as_str()) {
                    return Err(StorageError::Other(format!(
                        "smb: unsupported vers `{v}` (accepted: {})",
                        SMB_VERSIONS.join(", ")
                    )));
                }
                vers = Some(v);
            }
            ("credentials", Some(v)) | ("cred", Some(v)) => creds_path = Some(v),
            ("guest", None) => guest = true,
            // `password`/`pass` must never be declared inline in the store — the
            // password is a secrets-domain `SecretRef`, not a plaintext option.
            ("password" | "pass", _) => {
                return Err(StorageError::Other(
                    "smb: inline `password=` is not allowed in the option string; \
                     supply the password as a credential SecretRef"
                        .to_string(),
                ));
            }
            ("username" | "user", Some(v)) => username = Some(v),
            ("domain" | "dom", Some(v)) => domain = Some(v),
            ("uid", Some(v)) => uid = Some(v),
            ("gid", Some(v)) => gid = Some(v),
            ("iocharset", Some(v)) => iocharset = Some(v),
            ("noperm", None) => noperm = true,
            // Unknown-but-legal option: preserve it verbatim, order-stable.
            _ => extra.push(match opt.value {
                Some(v) => format!("{}={v}", opt.key),
                None => opt.key.to_string(),
            }),
        }
    }

    let credentials = resolve_smb_credentials(
        creds_path,
        guest,
        username,
        domain,
        spec.credential.as_ref(),
    )?;

    Ok(SmbOptions {
        vers,
        credentials,
        uid,
        gid,
        iocharset,
        noperm,
        extra,
    })
}

/// Reduce the parsed credential signals into exactly one coherent
/// [`SmbCredentials`], rejecting conflicting combinations.
fn resolve_smb_credentials(
    creds_path: Option<String>,
    guest: bool,
    username: Option<String>,
    domain: Option<String>,
    credential: Option<&SecretRef>,
) -> Result<SmbCredentials, StorageError> {
    match (creds_path, guest, username) {
        // More than one form declared at once — ambiguous, reject.
        (Some(_), true, _) => Err(StorageError::Other(
            "smb: `guest` and `credentials=` are mutually exclusive".to_string(),
        )),
        (Some(_), _, Some(_)) => Err(StorageError::Other(
            "smb: `credentials=` (file) and `username=` (inline) are mutually exclusive"
                .to_string(),
        )),
        (_, true, Some(_)) => Err(StorageError::Other(
            "smb: `guest` and `username=` are mutually exclusive".to_string(),
        )),
        // File credential form.
        (Some(path), false, None) => Ok(SmbCredentials::File { path }),
        // Inline form: requires a password SecretRef from the spec's credential.
        (None, false, Some(user)) => match credential {
            Some(secret) => Ok(SmbCredentials::Inline {
                username: user,
                password: secret.clone(),
                domain,
            }),
            None => Err(StorageError::Other(
                "smb: inline `username=` requires a credential SecretRef for the password"
                    .to_string(),
            )),
        },
        // Explicit guest.
        (None, true, None) => Ok(SmbCredentials::Guest),
        // Nothing declared: default to an anonymous (guest) mount.
        (None, false, None) => Ok(SmbCredentials::Guest),
    }
}

/// Render a validated [`SmbOptions`] for mount `target` into the canonical cifs
/// option string core stamps verbatim into `OptionSet::Raw`.
///
/// CREDENTIAL SAFETY (locked design decision): an inline username/password
/// credential is NEVER rendered inline into the option string — the autofs map /
/// mount `-o` string it feeds may be world-readable. Instead the inline form is
/// referenced through a root-written `credentials=<path>` file (the generic
/// [`SecretFile`] the backend hands core via
/// [`plugin_toolkit::storage::secret_file_path`]); the password (a [`SecretRef`])
/// is resolved and its plaintext written into that file by core's privileged 0600
/// writer, never by this renderer. The `File` form already references a
/// creds-file, and `Guest` renders `guest`.
pub fn render_smb_options(o: &SmbOptions, target: &str) -> String {
    // Build with the generic builder; every key/flag below is SMB grammar ours.
    let mut b = OptionBuilder::new();
    if let Some(v) = &o.vers {
        b.opt("vers", Some(v));
    }
    match &o.credentials {
        SmbCredentials::File { path } => {
            b.opt("credentials", Some(path));
        }
        // Inline: reference the root-written creds-file, NEVER inline user/pass.
        SmbCredentials::Inline { .. } => {
            b.opt("credentials", Some(&secret_file_path(target)));
        }
        SmbCredentials::Guest => {
            b.opt("guest", None);
        }
    }
    if let Some(v) = &o.uid {
        b.opt("uid", Some(v));
    }
    if let Some(v) = &o.gid {
        b.opt("gid", Some(v));
    }
    if let Some(v) = &o.iocharset {
        b.opt("iocharset", Some(v));
    }
    b.flag("noperm", o.noperm).extra(o.extra.clone());
    b.finish()
}

/// Build the generic [`SecretFile`] for an inline-credential mount: resolve the
/// password [`SecretRef`] to plaintext, render the cifs creds-file contents, and
/// point it at the core-owned deterministic [`secret_file_path`] (which
/// [`is_valid_secret_file_path`] round-trips, so core's allowlist admits the
/// write). Returns `None` for File/Guest credentials (no secret to materialize)
/// or (fail-closed) if the SecretRef cannot be resolved — the mount then
/// references a creds-file that does not exist and simply fails to authenticate,
/// which is safer than leaking or guessing.
fn build_secret_file(o: &SmbOptions, target: &str) -> Option<SecretFile> {
    let SmbCredentials::Inline {
        username,
        password,
        domain,
    } = &o.credentials
    else {
        return None;
    };
    let plaintext = match plugin_toolkit::secrets::get_required(&password.0) {
        Ok(p) => p,
        Err(_) => return None, // fail closed — never log the ref's value
    };
    let path = secret_file_path(target);
    if !is_valid_secret_file_path(&path) {
        return None;
    }
    Some(SecretFile {
        path,
        contents: render_creds_file(username, &plaintext, domain.as_deref()),
    })
}

// ── smb stale-session recovery (Phase 3) ─────────────────────────────────────
//
// SMB/CIFS has no stale-NFS-filehandle equivalent, but it does have dead-session
// recovery: when a server drops a session (reboot, network blip) a `hard`-mounted
// share wedges — I/O hangs and never idles out, exactly like a stale NFS mount.
// The recovery shape mirrors the nfs plugin: probe each managed mount, and for any
// that are stale/hung/missing, force-release (`umount -lf`) and retrigger so the
// kernel re-establishes the session. Modeled on nfs's `recover_stale`.

/// Force-release a wedged smb mount and retrigger it. `umount -lf` lazily detaches
/// even a session that is hanging on a dead server (a plain `-l` will not release
/// a `hard` cifs mount whose server is unreachable); the follow-up `stat` re-access
/// prompts the kernel/automount to re-establish the session. Returns
/// `(recovered, errors)`.
pub async fn force_and_retrigger(
    mountpoint: &Path,
    health_timeout: Duration,
) -> (bool, Vec<String>) {
    let mut errors = Vec::new();
    let mp = mountpoint.to_str().unwrap_or("");
    if which("umount").is_some() {
        if let Err(e) = run_tool("umount", &["-lf", "--", mp]).await {
            errors.push(format!("release {mp}: {e}"));
        }
    } else {
        errors.push("release: umount not found on PATH".to_string());
    }
    // Best-effort retrigger: accessing a direct-map mountpoint re-mounts it.
    if which("stat").is_some() {
        if let Err(e) = run_tool("stat", &["--", mp]).await {
            errors.push(format!("retrigger {mp}: {e}"));
        }
    }
    let recovered = health(mountpoint, health_timeout) == Health::Ok;
    (recovered, errors)
}

/// Probe every live smb mount (optionally filtered to the `watch` prefixes),
/// force-release + retrigger any that are stale/hung/missing, and report the
/// outcome. Mirrors the nfs plugin's `recover_stale`: healthy and
/// indeterminate-error probes are left untouched (never act on an ambiguous
/// signal). Only a failure to read the kernel mount table is fatal.
pub async fn recover_stale_mounts(
    watch: &[String],
    health_timeout: Duration,
) -> Result<RecoverOutcome, SmbError> {
    let mut out = RecoverOutcome::default();

    let mounts = list_mounts()?;
    for m in &mounts {
        // Honor the watch prefix filter (empty = all), matching nfs semantics.
        if !watch.is_empty()
            && !watch
                .iter()
                .any(|w| match m.mountpoint.strip_prefix(w.as_str()) {
                    Some("") => true,
                    Some(rest) => rest.starts_with('/'),
                    None => false,
                })
        {
            continue;
        }
        let mp = Path::new(&m.mountpoint);
        match health(mp, health_timeout) {
            Health::Ok => {}
            Health::Error => out.errors.push(format!(
                "probe {}: indeterminate error, left untouched",
                m.mountpoint
            )),
            Health::Stale | Health::Timeout | Health::Missing => {
                let (recovered, errs) = force_and_retrigger(mp, health_timeout).await;
                out.errors.extend(errs);
                if recovered {
                    out.recovered.push(m.mountpoint.clone());
                } else {
                    out.still_stale.push(m.mountpoint.clone());
                }
            }
        }
    }

    out.no_stale_found = out.recovered.is_empty() && out.still_stale.is_empty();
    Ok(out)
}

// ── storage domain backend ──────────────────────────────────────────────────

/// SMB/CIFS network-share backend for the `storage` domain. Contributes the
/// host's live SMB/CIFS mounts as shares, exposes unmount, owns its option +
/// credential grammar (`validate_spec` / `render_options`), and self-heals
/// dead-session mounts (`recover_stale`).
///
/// Mount is left at the default [`StorageError::Unsupported`]: smb mounts are
/// realized as kernel mounts through core's autofs applier (see
/// [`StorageBackend::mount_style`] → [`MountStyle::KernelMount`]), not driven by
/// this backend. Usage and server-share listing likewise stay unsupported here.
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

#[orca_async]
impl StorageBackend for SmbBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> StorageKind {
        StorageKind::NetworkShare
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::List,
            Capability::Unmount,
            Capability::RecoverStale,
        ]
    }

    fn endpoint(&self) -> String {
        "smb://local".to_string()
    }

    fn mount_style(&self) -> MountStyle {
        // smb mounts are kernel mounts driven through autofs / mount.cifs.
        MountStyle::KernelMount
    }

    async fn validate_spec(&self, spec: &StorageMountSpec) -> Result<NormalizedSpec, StorageError> {
        // Validate + render locally into the opaque `OptionSet::Raw` string core
        // carries, and populate the generic `SecretFile` for an inline-credential
        // mount (core writes it 0600 before mounting). Core owns neither the option
        // grammar nor the credential grammar.
        let options = validate_smb_options(spec)?;
        let rendered = render_smb_options(&options, &spec.target);
        let secret_file = build_secret_file(&options, &spec.target);
        Ok(NormalizedSpec {
            backend: spec.backend.clone(),
            target: spec.target.clone(),
            fstype: spec.fstype.clone(),
            source: spec.source.clone(),
            failover_sources: spec.failover_sources.clone(),
            options: OptionSet::Raw {
                options: Some(rendered),
            },
            credential: spec.credential.clone(),
            secret_file,
            remount_policy: spec.remount_policy.clone(),
            enabled: spec.enabled,
        })
    }

    /// Render the cifs option string core stamps into the map / `mount -o`. Core is
    /// fstype-agnostic: it hands an `OptionSet::Raw` holding either the declared
    /// option string (autofs map path) or the already-rendered string. Either way
    /// re-parse + re-render so credential safety (the `credentials=<path>`
    /// reference) is always applied.
    fn render_options(&self, spec: &NormalizedSpec) -> String {
        let OptionSet::Raw { options } = &spec.options;
        let mount_spec = StorageMountSpec {
            backend: spec.backend.clone(),
            target: spec.target.clone(),
            fstype: spec.fstype.clone(),
            source: spec.source.clone(),
            failover_sources: spec.failover_sources.clone(),
            options: options.clone(),
            credential: spec.credential.clone(),
            remount_policy: spec.remount_policy.clone(),
            enabled: spec.enabled,
        };
        match validate_smb_options(&mount_spec) {
            Ok(o) => render_smb_options(&o, &spec.target),
            Err(_) => options.clone().unwrap_or_default(),
        }
    }

    fn net_fstypes(&self) -> Vec<String> {
        vec!["cifs".to_string(), "smbfs".to_string()]
    }

    /// The SMB transport port core probes for source liveness. Core holds no
    /// port literal — it asks the fstype's owning backend, which is smb here.
    fn default_source_port(&self) -> Option<u16> {
        Some(445)
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

    async fn recover_stale(
        &self,
        watch: &[String],
        health_timeout: Duration,
    ) -> Result<RecoverOutcome, StorageError> {
        recover_stale_mounts(watch, health_timeout)
            .await
            .map_err(|e| StorageError::Transport(e.to_string()))
    }
}

/// Register the smb storage backend with the process-global `storage` registry.
/// Retained for the `rlib` shape (in-process embedding / tests); the runnable
/// plugin is the subprocess `[[bin]]`, which serves the backend directly via
/// `plugin_toolkit::serve_storage_plugin!` (see `main.rs`) and never calls this.
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

    // ── smb option grammar (Phase 3) ──────────────────────────────────────

    /// Build a `StorageMountSpec` for the option-grammar tests. `options` is the
    /// raw declared cifs option string; `credential` is the password `SecretRef`
    /// an inline mount carries.
    fn smb_spec(options: Option<&str>, credential: Option<&str>) -> StorageMountSpec {
        StorageMountSpec {
            backend: "smb".into(),
            target: "/mnt/media".into(),
            fstype: "cifs".into(),
            source: "//nas/media".into(),
            failover_sources: vec![],
            options: options.map(str::to_string),
            credential: credential.map(|s| SecretRef(s.to_string())),
            remount_policy: None,
            enabled: true,
        }
    }

    /// Validate + render an smb spec locally the way the backend does, returning
    /// the rendered cifs option string for `target`.
    fn render(spec: &StorageMountSpec) -> String {
        let o = validate_smb_options(spec).expect("valid spec");
        render_smb_options(&o, &spec.target)
    }

    #[test]
    fn validate_accepts_each_supported_vers() {
        for v in SMB_VERSIONS {
            let spec = smb_spec(Some(&format!("vers={v},guest")), None);
            let set = validate_smb_options(&spec).expect("supported vers accepted");
            assert_eq!(set.vers.as_deref(), Some(*v));
        }
    }

    #[test]
    fn validate_rejects_bad_vers() {
        let spec = smb_spec(Some("vers=9.9,guest"), None);
        let err = validate_smb_options(&spec).expect_err("bad vers rejected");
        assert!(err.to_string().contains("unsupported vers"), "got: {err}");
    }

    #[test]
    fn validate_accepts_guest() {
        let spec = smb_spec(Some("vers=3.0,guest"), None);
        let set = validate_smb_options(&spec).expect("guest accepted");
        assert!(matches!(set.credentials, SmbCredentials::Guest));
    }

    #[test]
    fn validate_accepts_file_credentials() {
        let spec = smb_spec(Some("vers=3.1.1,credentials=/etc/smb.creds,uid=1000"), None);
        let set = validate_smb_options(&spec).expect("file creds accepted");
        match set.credentials {
            SmbCredentials::File { path } => {
                assert_eq!(path, "/etc/smb.creds");
                assert_eq!(set.uid.as_deref(), Some("1000"));
            }
            other => panic!("expected File credentials, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_inline_with_secret_ref() {
        let spec = smb_spec(
            Some("vers=3.0,username=svc,domain=WORKGROUP"),
            Some("onepassword://vault/item"),
        );
        let set = validate_smb_options(&spec).expect("inline creds accepted");
        match set.credentials {
            SmbCredentials::Inline {
                username,
                password,
                domain,
            } => {
                assert_eq!(username, "svc");
                assert_eq!(password, SecretRef("onepassword://vault/item".into()));
                assert_eq!(domain.as_deref(), Some("WORKGROUP"));
            }
            other => panic!("expected Inline credentials, got {other:?}"),
        }
    }

    #[test]
    fn validate_defaults_to_guest_when_nothing_declared() {
        let spec = smb_spec(Some("vers=3.0,uid=1000"), None);
        let set = validate_smb_options(&spec).expect("defaults to guest");
        assert!(matches!(set.credentials, SmbCredentials::Guest));
    }

    #[test]
    fn validate_rejects_inline_without_secret_ref() {
        // username= with no password SecretRef is an incomplete inline form.
        let spec = smb_spec(Some("username=svc"), None);
        let err = validate_smb_options(&spec).expect_err("inline w/o secret rejected");
        assert!(err.to_string().contains("SecretRef"), "got: {err}");
    }

    #[test]
    fn validate_rejects_inline_plaintext_password() {
        // A plaintext password= in the option string is never allowed.
        let spec = smb_spec(Some("username=svc,password=hunter2"), Some("secret://x"));
        let err = validate_smb_options(&spec).expect_err("inline password rejected");
        assert!(err.to_string().contains("password"), "got: {err}");
    }

    #[test]
    fn validate_rejects_conflicting_guest_and_file() {
        let spec = smb_spec(Some("guest,credentials=/etc/smb.creds"), None);
        let err = validate_smb_options(&spec).expect_err("guest+file rejected");
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn validate_rejects_conflicting_file_and_inline() {
        let spec = smb_spec(
            Some("credentials=/etc/smb.creds,username=svc"),
            Some("secret://x"),
        );
        let err = validate_smb_options(&spec).expect_err("file+inline rejected");
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn validate_preserves_unknown_options_in_extra() {
        let spec = smb_spec(Some("guest,seal,cache=strict"), None);
        let set = validate_smb_options(&spec).expect("passthrough accepted");
        assert!(set.extra.contains(&"seal".to_string()));
        assert!(set.extra.contains(&"cache=strict".to_string()));
    }

    #[test]
    fn render_file_credentials_references_the_path() {
        let rendered = render(&smb_spec(
            Some("vers=3.0,credentials=/etc/smb.creds,uid=1000,noperm"),
            None,
        ));
        assert_eq!(
            rendered,
            "vers=3.0,credentials=/etc/smb.creds,uid=1000,noperm"
        );
    }

    #[test]
    fn render_guest_emits_guest() {
        assert_eq!(
            render(&smb_spec(Some("vers=3.1.1,guest"), None)),
            "vers=3.1.1,guest"
        );
    }

    #[test]
    fn render_inline_references_creds_file_never_plaintext() {
        // The locked property: an inline credential renders a `credentials=<path>`
        // REFERENCE — never inline `user=`/`username=`/`password=`, and never the
        // password SecretRef itself, into the world-readable option string.
        let secret = "onepassword://vault/smb-svc";
        let rendered = render(&smb_spec(
            Some("vers=3.0,username=svc,domain=WORKGROUP,uid=1000"),
            Some(secret),
        ));

        // References the deterministic core-owned root-written secret-file.
        assert!(
            rendered.contains(&format!("credentials={}", secret_file_path("/mnt/media"))),
            "expected secret-file reference, got: {rendered}"
        );
        // NEVER any inline credential material.
        assert!(!rendered.contains("password="), "no inline password=");
        assert!(!rendered.contains("username="), "no inline username=");
        assert!(!rendered.contains("user="), "no inline user=");
        assert!(!rendered.contains("domain="), "no inline domain=");
        // NEVER the secret ref / any secret scheme.
        assert!(!rendered.contains(secret), "secret ref must not render");
        assert!(!rendered.contains("onepassword"), "no secret scheme leak");
        // Non-secret typed options still render.
        assert!(rendered.contains("vers=3.0"));
        assert!(rendered.contains("uid=1000"));
    }

    #[test]
    fn secret_file_path_uses_core_slug_convention() {
        // The plugin references core's deterministic secret-file path so the
        // privileged allowlist (`is_valid_secret_file_path`) round-trips.
        let p = secret_file_path("/mnt/media");
        assert_eq!(p, "/etc/orca/secret-files/mnt_media.secret");
        assert!(is_valid_secret_file_path(&p));
    }

    #[tokio::test]
    async fn validate_spec_backend_method_normalizes_to_raw() {
        let backend = SmbBackend::new("smb");
        let spec = smb_spec(Some("vers=3.0,guest,uid=1000"), None);
        let normalized = backend.validate_spec(&spec).await.expect("validate");
        assert_eq!(
            normalized.options,
            OptionSet::Raw {
                options: Some("vers=3.0,guest,uid=1000".into())
            }
        );
        assert!(normalized.secret_file.is_none(), "guest has no secret-file");
        assert_eq!(
            backend.render_options(&normalized),
            "vers=3.0,guest,uid=1000"
        );
    }

    #[tokio::test]
    async fn validate_spec_backend_method_rejects_bad_vers() {
        let backend = SmbBackend::new("smb");
        let spec = smb_spec(Some("vers=1.5,guest"), None);
        assert!(backend.validate_spec(&spec).await.is_err());
    }

    #[test]
    fn mount_style_is_kernel_mount() {
        assert_eq!(SmbBackend::default().mount_style(), MountStyle::KernelMount);
    }

    #[test]
    fn capabilities_include_recover_stale() {
        let caps = SmbBackend::default().capabilities();
        assert!(caps.contains(&Capability::RecoverStale));
        assert!(caps.contains(&Capability::List));
        assert!(caps.contains(&Capability::Unmount));
    }

    #[test]
    fn recover_outcome_default_is_no_stale() {
        let o = RecoverOutcome::default();
        assert!(o.recovered.is_empty() && o.still_stale.is_empty());
    }
}
