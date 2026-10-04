//! rclone transport for the `smb` backup target: locating (or provisioning) the
//! rclone binary and running it against an on-the-fly `:smb:` remote.
//!
//! rclone speaks SMB entirely in userspace, so an unprivileged daemon (the
//! gaming boxes run orca as a plain user with no sudo) reaches the share with
//! no kernel mount and no FUSE. Connection details ride the environment, never
//! argv or a config file, so the password never lands on disk or in `ps`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use plugin_toolkit::client::{Client, Request};
use plugin_toolkit::hash::sha256_hex;
use plugin_toolkit::path::which;

/// The rclone release provisioned when none is on `PATH`.
pub const RCLONE_VERSION: &str = "v1.75.1";

/// SHA-256 of each pinned release zip, copied from that release's SHA256SUMS.
/// The live SHA256SUMS must agree with these, so a re-tagged or swapped asset
/// fails closed instead of being trusted on the strength of TLS alone.
const PINNED_SHA256: &[(&str, &str)] = &[
    (
        "amd64",
        "982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab",
    ),
    (
        "arm64",
        "03f2504174034b6d004152ed7369251c9a9ec1f7e0836eda420f5c7a5ec0dff9",
    ),
];

/// rclone exit code for "directory not found".
const EXIT_DIR_NOT_FOUND: i32 = 3;

static PROVISION: Mutex<()> = Mutex::new(());

/// Map a Rust target arch to rclone's release-asset arch.
pub fn release_arch(rust_arch: &str) -> Result<&'static str, String> {
    match rust_arch {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(format!("no pinned rclone build for arch `{other}`")),
    }
}

fn pinned_sha256(arch: &str) -> Result<&'static str, String> {
    PINNED_SHA256
        .iter()
        .find(|(a, _)| *a == arch)
        .map(|(_, d)| *d)
        .ok_or_else(|| format!("no pinned rclone digest for arch `{arch}`"))
}

/// `rclone-<version>-linux-<arch>.zip`.
pub fn asset_name(arch: &str) -> String {
    format!("rclone-{RCLONE_VERSION}-linux-{arch}.zip")
}

fn release_url(file: &str) -> String {
    format!("https://github.com/rclone/rclone/releases/download/{RCLONE_VERSION}/{file}")
}

/// The digest SHA256SUMS lists for `asset`. The file is PGP clear-signed, so
/// header/signature lines are skipped by requiring the `<hex>  <name>` shape.
pub fn sha256sums_lookup(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let digest = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        (name == asset && digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| digest.to_ascii_lowercase())
    })
}

/// Verify a downloaded `asset` against both the release's SHA256SUMS and the
/// digest pinned in this build.
pub fn verify_download(sums: &str, asset: &str, pinned: &str, bytes: &[u8]) -> Result<(), String> {
    let listed = sha256sums_lookup(sums, asset)
        .ok_or_else(|| format!("SHA256SUMS does not list {asset}"))?;
    if listed != pinned {
        return Err(format!(
            "SHA256SUMS digest for {asset} ({listed}) does not match the pinned digest ({pinned})"
        ));
    }
    let actual = sha256_hex(bytes);
    if actual != pinned {
        return Err(format!(
            "downloaded {asset} has sha256 {actual}, expected {pinned}"
        ));
    }
    Ok(())
}

/// Where a provisioned rclone lives: `<orca state dir>/tools/rclone/<version>/`.
/// Orca-private and version-scoped, so it never shadows a user-managed rclone
/// and a pin bump never runs a stale binary.
pub fn install_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tools").join("rclone").join(RCLONE_VERSION)
}

/// The rclone to run: one already on `PATH`, else the pinned build, downloaded
/// and verified on first use.
pub fn resolve() -> Result<PathBuf, String> {
    if let Some(p) = which("rclone") {
        return Ok(PathBuf::from(p));
    }
    let state = plugin_toolkit::contract::config::state_dir().map_err(|e| format!("{e:#}"))?;
    let arch = release_arch(std::env::consts::ARCH)?;
    let _guard = PROVISION.lock().unwrap_or_else(|e| e.into_inner());
    provision(
        &install_dir(&state),
        &asset_name(arch),
        pinned_sha256(arch)?,
        &http_fetch,
        &extract_member,
    )
}

/// Install rclone from `asset` into `dir` unless already present. The zip is
/// verified before anything is extracted, and the binary is renamed into place
/// only once complete, so a failure never leaves a runnable partial.
pub fn provision(
    dir: &Path,
    asset: &str,
    pinned: &str,
    fetch: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    extract: &dyn Fn(&Path, &str, &Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let bin = dir.join("rclone");
    if bin.is_file() {
        return Ok(bin);
    }
    let sums = fetch(&release_url("SHA256SUMS"))?;
    let zip = fetch(&release_url(asset))?;
    verify_download(&String::from_utf8_lossy(&sums), asset, pinned, &zip)?;

    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let zip_path = dir.join(format!("{asset}.partial"));
    fs::write(&zip_path, &zip).map_err(|e| format!("write {}: {e}", zip_path.display()))?;
    let staged = dir.join("rclone.partial");
    let member = format!("{}/rclone", asset.trim_end_matches(".zip"));
    let extracted = extract(&zip_path, &member, &staged);
    drop(fs::remove_file(&zip_path));
    extracted?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", staged.display()))?;
    }
    fs::rename(&staged, &bin).map_err(|e| format!("install {}: {e}", bin.display()))?;
    Ok(bin)
}

/// GET `url` through orca's delegated HTTP (the daemon owns TLS + redirects).
fn http_fetch(url: &str) -> Result<Vec<u8>, String> {
    let mut stream = Client::new()
        .stream(Request::new("GET", url).timeout_ms(600_000))
        .map_err(|e| format!("GET {url}: {e:#}"))?;
    if !stream.is_success() {
        return Err(format!("GET {url}: HTTP {}", stream.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = stream.next() {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Extract one zip member to `dest` with whichever stock extractor the host
/// has. The plugin links no zip codec, and the target hosts ship at least one.
fn extract_member(zip: &Path, member: &str, dest: &Path) -> Result<(), String> {
    const PY: &str = "import sys,zipfile; \
        sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))";
    let zip_s = zip.to_string_lossy();
    let candidates: [(&str, Vec<&str>); 3] = [
        ("unzip", vec!["-p", &zip_s, member]),
        ("bsdtar", vec!["-xOf", &zip_s, member]),
        ("python3", vec!["-c", PY, &zip_s, member]),
    ];
    let (tool, args) = candidates
        .iter()
        .find(|(tool, _)| which(tool).is_some())
        .ok_or("no zip extractor found (need one of unzip, bsdtar, python3)")?;
    let out = fs::File::create(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let status = Command::new(tool)
        .args(args)
        .stdout(out)
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("run {tool}: {e}"))?;
    if !status.status.success() {
        drop(fs::remove_file(dest));
        return Err(format!(
            "{tool} failed to extract {member}: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    Ok(())
}

/// The environment that points rclone's SMB backend at a server. The password
/// must already be obscured (`rclone obscure`), which is what `RCLONE_SMB_PASS`
/// expects. `RCLONE_CONFIG=/dev/null` keeps a user's own rclone config from
/// shadowing or leaking into the on-the-fly remote.
pub fn smb_env(host: &str, user: &str, obscured_pass: &str) -> Vec<(String, String)> {
    vec![
        ("RCLONE_CONFIG".into(), "/dev/null".into()),
        ("RCLONE_SMB_HOST".into(), host.into()),
        ("RCLONE_SMB_USER".into(), user.into()),
        ("RCLONE_SMB_PASS".into(), obscured_pass.into()),
    ]
}

/// The on-the-fly remote for `share`/`path`: `:smb:<share>[/<path>]`.
pub fn remote_root(share: &str, path: &str) -> String {
    let share = share.trim_matches('/');
    let path = path.trim_matches('/');
    if path.is_empty() {
        format!(":smb:{share}")
    } else {
        format!(":smb:{share}/{path}")
    }
}

/// Escape rclone filter glob metacharacters so a slot path matches literally.
pub fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ']' | '{' | '}') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A failed rclone run, its stderr already scrubbed of secrets.
#[derive(Debug)]
pub struct RcloneFailure {
    pub code: Option<i32>,
    pub stderr: String,
}

impl std::fmt::Display for RcloneFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rclone failed (exit {:?}): {}", self.code, self.stderr)
    }
}

/// An rclone binary bound to one SMB server's credentials.
pub struct Rclone {
    bin: PathBuf,
    env: Vec<(String, String)>,
    secrets: Vec<String>,
}

impl Rclone {
    /// Bind `bin` to an SMB server, obscuring `password` through rclone's stdin
    /// so the plaintext never appears in argv.
    pub fn connect(bin: PathBuf, host: &str, user: &str, password: &str) -> Result<Self, String> {
        let obscured = obscure(&bin, password)?;
        Ok(Self::with_obscured(bin, host, user, password, &obscured))
    }

    pub(crate) fn with_obscured(
        bin: PathBuf,
        host: &str,
        user: &str,
        password: &str,
        obscured: &str,
    ) -> Self {
        Self {
            bin,
            env: smb_env(host, user, obscured),
            secrets: vec![password.to_string(), obscured.to_string()],
        }
    }

    pub(crate) fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        cmd
    }

    /// Redact both forms of the password, then the shared secret patterns.
    pub(crate) fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for s in self.secrets.iter().filter(|s| !s.is_empty()) {
            out = out.replace(s.as_str(), "***");
        }
        out.lines()
            .map(|l| plugin_toolkit::scrub::scrub_line(l).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Run rclone, feeding `stdin` if given, and return stdout.
    pub fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, RcloneFailure> {
        let mut cmd = self.command(args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| RcloneFailure {
            code: None,
            stderr: format!("spawn {}: {e}", self.bin.display()),
        })?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes())
                .map_err(|e| RcloneFailure {
                    code: None,
                    stderr: format!("write rclone stdin: {e}"),
                })?;
        }
        let out = child.wait_with_output().map_err(|e| RcloneFailure {
            code: None,
            stderr: format!("wait for rclone: {e}"),
        })?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(RcloneFailure {
                code: out.status.code(),
                stderr: self.scrub(String::from_utf8_lossy(&out.stderr).trim()),
            })
        }
    }

    /// Committed slot paths under `root`: parents of `manifest.json`, never
    /// descending into a slot's `payload/` (as the generic store does). A root
    /// that does not exist yet lists as empty.
    pub fn list_slots(&self, root: &str) -> Result<BTreeSet<String>, String> {
        let args = [
            "lsf",
            "-R",
            "--files-only",
            "--filter",
            "- payload/**",
            "--filter",
            "+ manifest.json",
            "--filter",
            "- **",
            root,
        ];
        match self.run(&args, None) {
            Ok(out) => Ok(parse_manifest_listing(&out)),
            Err(e) if e.code == Some(EXIT_DIR_NOT_FOUND) => Ok(BTreeSet::new()),
            Err(e) => Err(format!("list {root}: {e}")),
        }
    }

    /// `rclone copy src dst`, restricted to the given slot subtrees. Payloads go
    /// first and each `manifest.json` only after every payload landed, so an
    /// interrupted copy never leaves a slot that looks committed but is partial
    /// on the receiving side; the next copy repairs it as a delta.
    pub fn copy_slots(&self, src: &str, dst: &str, slots: &BTreeSet<String>) -> Result<(), String> {
        for filter in copy_filters(slots) {
            self.run(&["copy", "--filter-from", "-", src, dst], Some(&filter))
                .map_err(|e| format!("copy {src} -> {dst}: {e}"))?;
        }
        Ok(())
    }

    /// Delete `path` and everything under it; already-absent is success.
    /// Backends disagree on the exit code for a missing path, so a failure is
    /// re-checked with `lsf` before it counts.
    pub fn purge(&self, path: &str) -> Result<(), String> {
        let Err(e) = self.run(&["purge", path], None) else {
            return Ok(());
        };
        match self.run(&["lsf", path], None) {
            Err(gone) if gone.code == Some(EXIT_DIR_NOT_FOUND) => Ok(()),
            _ => Err(format!("purge {path}: {e}")),
        }
    }

    /// Whether `a` and `b` hold the same files. Any failure reads as "differs".
    pub fn identical(&self, a: &str, b: &str) -> bool {
        self.run(&["check", a, b], None).is_ok()
    }
}

/// `rclone obscure -` reads the password from stdin.
fn obscure(bin: &Path, password: &str) -> Result<String, String> {
    let rc = Rclone {
        bin: bin.to_path_buf(),
        env: vec![("RCLONE_CONFIG".into(), "/dev/null".into())],
        secrets: vec![password.to_string()],
    };
    let out = rc
        .run(&["obscure", "-"], Some(&format!("{password}\n")))
        .map_err(|e| format!("obscure smb password: {e}"))?;
    let obscured = out.trim().to_string();
    if obscured.is_empty() {
        return Err("rclone obscure returned nothing".into());
    }
    Ok(obscured)
}

/// The two `--filter-from` passes for [`Rclone::copy_slots`]: every slot minus
/// its manifest, then every slot whole (only the manifests are left to move).
pub fn copy_filters(slots: &BTreeSet<String>) -> [String; 2] {
    let mut payloads = String::new();
    let mut whole = String::new();
    for s in slots {
        let s = escape_glob(s);
        payloads.push_str(&format!("- /{s}/manifest.json\n+ /{s}/**\n"));
        whole.push_str(&format!("+ /{s}/**\n"));
    }
    payloads.push_str("- **\n");
    whole.push_str("- **\n");
    [payloads, whole]
}

/// Turn `lsf` output (`<slot>/manifest.json` lines) into slot paths, dropping
/// anything inside a payload or that would escape the root.
pub fn parse_manifest_listing(out: &str) -> BTreeSet<String> {
    out.lines()
        .filter_map(|line| line.trim_end().strip_suffix("/manifest.json"))
        .filter(|slot| is_safe_slot(slot))
        .map(str::to_string)
        .collect()
}

/// A relative, `/`-separated path with no empty, `.`, `..` or `payload`
/// segment.
pub fn is_safe_slot(slot: &str) -> bool {
    !slot.is_empty()
        && slot
            .split('/')
            .all(|seg| !matches!(seg, "" | "." | ".." | "payload"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn sums_for(asset: &str, digest: &str) -> String {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1\n\n\
             {}  rclone-v0-other.zip\n{digest}  {asset}\n\
             -----BEGIN PGP SIGNATURE-----\nabc\n",
            "0".repeat(64)
        )
    }

    #[test]
    fn release_arch_maps_supported_and_rejects_others() {
        assert_eq!(release_arch("x86_64").unwrap(), "amd64");
        assert_eq!(release_arch("aarch64").unwrap(), "arm64");
        assert!(release_arch("riscv64").is_err());
        assert!(pinned_sha256("amd64").is_ok());
        assert!(pinned_sha256("arm64").is_ok());
    }

    #[test]
    fn sha256sums_lookup_skips_pgp_framing() {
        let d = "a".repeat(64);
        let sums = sums_for("rclone-x.zip", &d);
        assert_eq!(sha256sums_lookup(&sums, "rclone-x.zip"), Some(d));
        assert_eq!(sha256sums_lookup(&sums, "missing.zip"), None);
        assert_eq!(sha256sums_lookup("Hash: SHA1", "SHA1"), None);
    }

    #[test]
    fn verify_download_requires_sums_pin_and_bytes_to_agree() {
        let bytes = b"zip-bytes";
        let good = sha256_hex(bytes);
        let sums = sums_for("a.zip", &good);
        assert!(verify_download(&sums, "a.zip", &good, bytes).is_ok());
        // Tampered bytes.
        assert!(verify_download(&sums, "a.zip", &good, b"evil").is_err());
        // SHA256SUMS disagrees with the pin.
        let other = sums_for("a.zip", &"b".repeat(64));
        assert!(verify_download(&other, "a.zip", &good, bytes).is_err());
        // Asset not listed.
        assert!(verify_download(&sums, "b.zip", &good, bytes).is_err());
    }

    #[test]
    fn provision_installs_verified_binary_once() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("v");
        let zip = b"fake-zip".to_vec();
        let digest = sha256_hex(&zip);
        let fetched = RefCell::new(Vec::new());
        let fetch = |url: &str| -> Result<Vec<u8>, String> {
            fetched.borrow_mut().push(url.to_string());
            if url.ends_with("SHA256SUMS") {
                Ok(sums_for("r.zip", &digest).into_bytes())
            } else {
                Ok(zip.clone())
            }
        };
        let extract = |_zip: &Path, member: &str, dest: &Path| -> Result<(), String> {
            assert_eq!(member, "r/rclone");
            fs::write(dest, b"#!/bin/sh\n").map_err(|e| e.to_string())
        };
        let bin = provision(&install, "r.zip", &digest, &fetch, &extract).unwrap();
        assert_eq!(bin, install.join("rclone"));
        assert!(bin.is_file());
        assert!(!install.join("r.zip.partial").exists());
        assert!(!install.join("rclone.partial").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&bin).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        assert_eq!(fetched.borrow().len(), 2);

        // Already installed: no network.
        provision(&install, "r.zip", &digest, &fetch, &extract).unwrap();
        assert_eq!(fetched.borrow().len(), 2);
    }

    #[test]
    fn provision_refuses_a_checksum_mismatch_before_extracting() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = sha256_hex(b"the real zip");
        let fetch = |url: &str| -> Result<Vec<u8>, String> {
            if url.ends_with("SHA256SUMS") {
                Ok(sums_for("r.zip", &pinned).into_bytes())
            } else {
                Ok(b"tampered zip".to_vec())
            }
        };
        let extracted = RefCell::new(false);
        let extract = |_: &Path, _: &str, _: &Path| -> Result<(), String> {
            *extracted.borrow_mut() = true;
            Ok(())
        };
        let err = provision(dir.path(), "r.zip", &pinned, &fetch, &extract).unwrap_err();
        assert!(err.contains("sha256"), "{err}");
        assert!(!*extracted.borrow());
        assert!(!dir.path().join("rclone").exists());
    }

    #[test]
    fn provision_leaves_no_binary_when_extraction_fails() {
        let dir = tempfile::tempdir().unwrap();
        let zip = b"z".to_vec();
        let digest = sha256_hex(&zip);
        let fetch = |url: &str| -> Result<Vec<u8>, String> {
            if url.ends_with("SHA256SUMS") {
                Ok(sums_for("r.zip", &digest).into_bytes())
            } else {
                Ok(zip.clone())
            }
        };
        let extract = |_: &Path, _: &str, _: &Path| -> Result<(), String> { Err("boom".into()) };
        assert!(provision(dir.path(), "r.zip", &digest, &fetch, &extract).is_err());
        assert!(!dir.path().join("rclone").exists());
        assert!(!dir.path().join("r.zip.partial").exists());
    }

    #[test]
    fn install_dir_is_orca_private_and_version_scoped() {
        let d = install_dir(Path::new("/home/u/.orca"));
        assert_eq!(
            d,
            PathBuf::from(format!("/home/u/.orca/tools/rclone/{RCLONE_VERSION}"))
        );
    }

    #[test]
    fn password_never_reaches_argv_only_obscured_env() {
        let rc = Rclone::with_obscured(
            PathBuf::from("/bin/rclone"),
            "10.0.0.5",
            "skey",
            "hunter2",
            "OBSCURED",
        );
        let cmd = rc.command(&["lsf", ":smb:backups/game-saves"]);
        for arg in cmd.get_args() {
            let arg = arg.to_string_lossy();
            assert!(!arg.contains("hunter2"));
            assert!(!arg.contains("OBSCURED"));
        }
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert!(envs.contains(&("RCLONE_SMB_PASS".into(), "OBSCURED".into())));
        assert!(envs.contains(&("RCLONE_SMB_HOST".into(), "10.0.0.5".into())));
        assert!(envs.contains(&("RCLONE_SMB_USER".into(), "skey".into())));
        assert!(envs.contains(&("RCLONE_CONFIG".into(), "/dev/null".into())));
        assert!(envs.iter().all(|(_, v)| !v.contains("hunter2")));
    }

    #[test]
    fn scrub_redacts_plain_and_obscured_password() {
        let rc = Rclone::with_obscured(PathBuf::from("rclone"), "h", "u", "hunter2", "OBSC");
        let out = rc.scrub("auth failed for hunter2\nRCLONE_SMB_PASS=OBSC");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("OBSC"));
    }

    #[test]
    fn remote_root_joins_share_and_path() {
        assert_eq!(
            remote_root("backups", "game-saves"),
            ":smb:backups/game-saves"
        );
        assert_eq!(remote_root("/backups/", "/a/b/"), ":smb:backups/a/b");
        assert_eq!(remote_root("backups", ""), ":smb:backups");
    }

    #[test]
    fn escape_glob_makes_metacharacters_literal() {
        assert_eq!(escape_glob("game [EU]/x*y"), r"game \[EU\]/x\*y");
        assert_eq!(escape_glob("a{b}?c\\"), r"a\{b\}\?c\\");
        assert_eq!(escape_glob("plain-1"), "plain-1");
    }

    #[test]
    fn copy_filters_hold_manifests_back_until_the_second_pass() {
        let slots: BTreeSet<String> = ["g/a/1".to_string(), "g/[b]/2".to_string()].into();
        let [payloads, whole] = copy_filters(&slots);
        assert_eq!(
            payloads,
            "- /g/[b]/2/manifest.json\n+ /g/[b]/2/**\n- /g/a/1/manifest.json\n+ /g/a/1/**\n- **\n"
                .replace("[b]", r"\[b\]")
        );
        assert_eq!(whole, "+ /g/\\[b\\]/2/**\n+ /g/a/1/**\n- **\n");
    }

    #[test]
    fn parse_manifest_listing_keeps_slots_and_drops_unsafe() {
        let out = "\
game-saves/bragi/20261004-030000/manifest.json
game-saves/bragi/20261004-030000/payload/manifest.json
manifest.json
../escape/manifest.json
a//b/manifest.json
game-saves/x/notes.txt
";
        let slots = parse_manifest_listing(out);
        assert_eq!(
            slots.into_iter().collect::<Vec<_>>(),
            vec!["game-saves/bragi/20261004-030000".to_string()]
        );
    }
}
