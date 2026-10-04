//! rclone transport for the `smb` backup target: locating (or provisioning) the
//! rclone binary and running it against an on-the-fly `:smb:` remote.
//!
//! rclone speaks SMB entirely in userspace, so an unprivileged daemon (the
//! gaming boxes run orca as a plain user with no sudo) reaches the share with
//! no kernel mount and no FUSE. Connection details ride the environment, never
//! argv or a config file, so the password never lands on disk or in `ps`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use plugin_toolkit::client::{Client, Request};
use plugin_toolkit::hash::{sha256_file, sha256_hex};
use plugin_toolkit::path::which;

/// The rclone release this plugin pins.
pub const RCLONE_VERSION: &str = "v1.75.1";

/// Digests for one pinned release asset. `zip` is copied from the release's
/// SHA256SUMS (which must agree at download time, so a re-tagged or swapped
/// asset fails closed); `bin` is the extracted `rclone` binary itself.
#[derive(Debug, Clone, Copy)]
pub struct Pin<'a> {
    pub arch: &'a str,
    pub zip: &'a str,
    pub bin: &'a str,
}

const PINS: &[Pin<'static>] = &[
    Pin {
        arch: "amd64",
        zip: "982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab",
        bin: "f66d8c1d552ad90296a11bc8b46d56a7fa5da1a7fa05e7ca522d95df92c4a4c0",
    },
    Pin {
        arch: "arm64",
        zip: "03f2504174034b6d004152ed7369251c9a9ec1f7e0836eda420f5c7a5ec0dff9",
        bin: "d7ecfc17726b34f95c5f7ea9470862c2aef53dce1bb0677b83142ca38503f489",
    },
];

/// rclone exit code for "directory not found".
const EXIT_DIR_NOT_FOUND: i32 = 3;

/// Network knobs on every call, so a dead or wedged server fails in bounded
/// time instead of holding the plugin's invoke thread.
const NET_FLAGS: &[&str] = &[
    "--contimeout",
    "30s",
    "--timeout",
    "2m",
    "--retries",
    "3",
    "--low-level-retries",
    "5",
];

/// The only inherited variables rclone sees; everything else (a stray
/// `RCLONE_*`, proxies, the daemon's own secrets) is cleared.
const ENV_PASSTHROUGH: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG"];

/// Wall-clock cap for listing/metadata calls.
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Wall-clock cap for one copy pass.
pub const COPY_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Largest `manifest.json` accepted from the remote.
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;

static RESOLVED: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Map a Rust target arch to rclone's release-asset arch.
pub fn release_arch(rust_arch: &str) -> Result<&'static str, String> {
    match rust_arch {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(format!("no pinned rclone build for arch `{other}`")),
    }
}

fn pin_for(arch: &str) -> Option<Pin<'static>> {
    PINS.iter().find(|p| p.arch == arch).copied()
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

/// Where the pinned rclone lives: `<orca state dir>/tools/rclone/<version>/`.
/// Orca-private and version-scoped, so it never shadows a user-managed rclone
/// and a pin bump never runs a stale binary.
pub fn install_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tools").join("rclone").join(RCLONE_VERSION)
}

/// `(major, minor, patch)` from `rclone version` output (`rclone v1.75.1…`).
pub fn parse_version(out: &str) -> Option<(u64, u64, u64)> {
    let v = out
        .lines()
        .next()?
        .split_whitespace()
        .find_map(|t| t.strip_prefix('v'))?;
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|n| n.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// The rclone to run, verified once per process: the pinned build (installed
/// or, on Linux, downloaded and checked), else an rclone on `PATH` at least as
/// new as the pin.
pub fn resolve() -> Result<PathBuf, String> {
    let mut cached = RESOLVED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cached.as_ref() {
        return Ok(p.clone());
    }
    let state = plugin_toolkit::contract::config::state_dir().map_err(|e| format!("{e:#}"))?;
    let arch = release_arch(std::env::consts::ARCH).ok();
    let bin = resolve_with(&Resolver {
        dir: &install_dir(&state),
        os: std::env::consts::OS,
        asset: arch.map(asset_name).unwrap_or_default(),
        pin: arch.and_then(pin_for),
        on_path: which("rclone"),
        fetch: &http_fetch,
        extract: &extract_member,
        version_of: &|bin: &Path| {
            Rclone::bare(bin.to_path_buf())
                .run(&["version"], None, SHORT_TIMEOUT)
                .map_err(|e| e.to_string())
        },
    })?;
    *cached = Some(bin.clone());
    Ok(bin)
}

/// Inputs to [`resolve_with`], split out so the selection order is testable.
pub struct Resolver<'a> {
    pub dir: &'a Path,
    pub os: &'a str,
    pub asset: String,
    pub pin: Option<Pin<'a>>,
    pub on_path: Option<String>,
    pub fetch: &'a dyn Fn(&str) -> Result<Vec<u8>, String>,
    pub extract: &'a dyn Fn(&Path, &str, &Path) -> Result<(), String>,
    pub version_of: &'a dyn Fn(&Path) -> Result<String, String>,
}

pub fn resolve_with(r: &Resolver<'_>) -> Result<PathBuf, String> {
    let mut why = Vec::new();
    if let Some(pin) = r.pin {
        if let Some(bin) = installed(r.dir, pin.bin)? {
            return Ok(bin);
        }
        if r.os == "linux" {
            match provision(r.dir, &r.asset, pin, r.fetch, r.extract) {
                Ok(bin) => return Ok(bin),
                Err(e) => why.push(format!("provisioning failed: {e}")),
            }
        } else {
            why.push(format!("no pinned rclone build for {}", r.os));
        }
    } else {
        why.push("no pinned rclone build for this arch".to_string());
    }
    match r.on_path.as_deref() {
        Some(p) if Path::new(p).is_absolute() => {
            let min = parse_version(RCLONE_VERSION).expect("pinned version parses");
            let out = (r.version_of)(Path::new(p))?;
            match parse_version(&out) {
                Some(v) if v >= min => return Ok(PathBuf::from(p)),
                v => why.push(format!(
                    "rclone on PATH ({p}) is {v:?}, older than the pinned {RCLONE_VERSION}"
                )),
            }
        }
        Some(p) => why.push(format!("ignoring non-absolute rclone path `{p}`")),
        None => why.push("no rclone on PATH".to_string()),
    }
    Err(format!("no usable rclone: {}", why.join("; ")))
}

/// The installed pinned binary, if present and still matching its digest. A
/// mismatch is removed so it is re-provisioned rather than run.
fn installed(dir: &Path, bin_digest: &str) -> Result<Option<PathBuf>, String> {
    let bin = dir.join("rclone");
    if !bin.is_file() {
        return Ok(None);
    }
    let actual = sha256_file(&bin).map_err(|e| format!("{e:#}"))?;
    if actual == bin_digest {
        return Ok(Some(bin));
    }
    fs::remove_file(&bin).map_err(|e| format!("remove tampered {}: {e}", bin.display()))?;
    Ok(None)
}

fn unique() -> String {
    format!("{}.{}", std::process::id(), plugin_toolkit::id::new())
}

fn fsync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        drop(d.sync_all());
    }
}

/// Install the pinned rclone from `asset` into `dir`. Both the zip and the
/// extracted binary are checked against the pin, and the binary is fsynced and
/// renamed into place only once verified, so a failure never leaves a runnable
/// partial.
pub fn provision(
    dir: &Path,
    asset: &str,
    pin: Pin<'_>,
    fetch: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    extract: &dyn Fn(&Path, &str, &Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let bin = dir.join("rclone");
    let sums = fetch(&release_url("SHA256SUMS"))?;
    let zip = fetch(&release_url(asset))?;
    verify_download(&String::from_utf8_lossy(&sums), asset, pin.zip, &zip)?;

    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tag = unique();
    let zip_path = dir.join(format!("{asset}.{tag}.partial"));
    fs::write(&zip_path, &zip).map_err(|e| format!("write {}: {e}", zip_path.display()))?;
    let staged = dir.join(format!("rclone.{tag}.partial"));
    let member = format!("{}/rclone", asset.trim_end_matches(".zip"));
    let extracted = extract(&zip_path, &member, &staged);
    drop(fs::remove_file(&zip_path));
    let installed = extracted.and_then(|()| finish_install(&staged, &bin, pin.bin));
    if installed.is_err() {
        drop(fs::remove_file(&staged));
    }
    installed?;
    fsync_dir(dir);
    Ok(bin)
}

fn finish_install(staged: &Path, bin: &Path, bin_digest: &str) -> Result<(), String> {
    let actual = sha256_file(staged).map_err(|e| format!("{e:#}"))?;
    if actual != bin_digest {
        return Err(format!(
            "extracted rclone has sha256 {actual}, expected {bin_digest}"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", staged.display()))?;
    }
    fs::File::open(staged)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync {}: {e}", staged.display()))?;
    fs::rename(staged, bin).map_err(|e| format!("install {}: {e}", bin.display()))
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
    deadline: Option<Instant>,
}

impl Rclone {
    /// Bind `bin` to an SMB server, obscuring `password` through rclone's stdin
    /// so the plaintext never appears in argv.
    pub fn connect(bin: PathBuf, host: &str, user: &str, password: &str) -> Result<Self, String> {
        let mut bare = Self::bare(bin.clone());
        bare.secrets.push(password.to_string());
        let out = bare
            .run(
                &["obscure", "-"],
                Some(&format!("{password}\n")),
                SHORT_TIMEOUT,
            )
            .map_err(|e| format!("obscure smb password: {e}"))?;
        let obscured = out.trim();
        if obscured.is_empty() {
            return Err("rclone obscure returned nothing".into());
        }
        Ok(Self::with_obscured(bin, host, user, password, obscured))
    }

    pub(crate) fn bare(bin: PathBuf) -> Self {
        Self {
            bin,
            env: vec![("RCLONE_CONFIG".into(), "/dev/null".into())],
            secrets: Vec::new(),
            deadline: None,
        }
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
            deadline: None,
        }
    }

    /// Cap every later call so the whole sequence ends by `deadline`.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub(crate) fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        if let Some((sub, rest)) = args.split_first() {
            cmd.arg(sub).args(NET_FLAGS).args(rest);
        }
        cmd.env_clear();
        for k in ENV_PASSTHROUGH {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        cmd.envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
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

    /// Run rclone, feeding `stdin` if given, and return stdout. The child is
    /// killed and reaped once `timeout` (or the overall deadline) passes.
    pub fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<String, RcloneFailure> {
        let fail = |stderr: String| RcloneFailure { code: None, stderr };
        let now = Instant::now();
        let deadline = match self.deadline {
            Some(d) => d.min(now + timeout),
            None => now + timeout,
        };
        if deadline <= now {
            return Err(fail("reconcile deadline exceeded".into()));
        }
        let mut cmd = self.command(args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| fail(format!("spawn {}: {e}", self.bin.display())))?;
        let drain = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut p) = pipe {
                    drop(p.read_to_end(&mut buf));
                }
                buf
            })
        };
        let out = drain(child.stdout.take().map(|p| Box::new(p) as _));
        let err = drain(child.stderr.take().map(|p| Box::new(p) as _));
        let write_err = match (stdin, child.stdin.take()) {
            (Some(input), Some(mut pipe)) => pipe.write_all(input.as_bytes()).err(),
            _ => None,
        };

        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() >= deadline => {
                    timed_out = true;
                    drop(child.kill());
                    break child.wait().ok();
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(_) => break child.wait().ok(),
            }
        };
        let stdout = out.join().unwrap_or_default();
        let stderr = self.scrub(String::from_utf8_lossy(&err.join().unwrap_or_default()).trim());

        if timed_out {
            return Err(fail(format!(
                "timed out after {timeout:?}; killed: {stderr}"
            )));
        }
        match status {
            Some(s) if s.success() && write_err.is_none() => {
                Ok(String::from_utf8_lossy(&stdout).into_owned())
            }
            Some(s) if s.success() => Err(fail(format!(
                "write rclone stdin: {}",
                write_err.map(|e| e.to_string()).unwrap_or_default()
            ))),
            Some(s) => Err(RcloneFailure {
                code: s.code(),
                stderr,
            }),
            None => Err(fail(format!("could not reap rclone: {stderr}"))),
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
        match self.run(&args, None, SHORT_TIMEOUT) {
            Ok(out) => Ok(parse_manifest_listing(&out)),
            Err(e) if e.code == Some(EXIT_DIR_NOT_FOUND) => Ok(BTreeSet::new()),
            Err(e) => Err(format!("list {root}: {e}")),
        }
    }

    /// Push slots from `src` to `dst`: payloads first, then each
    /// `manifest.json`, so an interrupted push never leaves a remote slot that
    /// looks committed but is partial.
    pub fn push_slots(&self, src: &str, dst: &str, slots: &BTreeSet<String>) -> Result<(), String> {
        for filter in push_filters(slots) {
            self.run(
                &["copy", "--filter-from", "-", src, dst],
                Some(&filter),
                COPY_TIMEOUT,
            )
            .map_err(|e| format!("copy {src} -> {dst}: {e}"))?;
        }
        Ok(())
    }

    /// Copy only the payloads of `slots` from `src` into `dst`, never
    /// overwriting a file that already exists there.
    pub fn pull_payloads(
        &self,
        src: &str,
        dst: &str,
        slots: &BTreeSet<String>,
    ) -> Result<(), String> {
        let [payloads, _] = push_filters(slots);
        self.run(
            &["copy", "--ignore-existing", "--filter-from", "-", src, dst],
            Some(&payloads),
            COPY_TIMEOUT,
        )
        .map(|_| ())
        .map_err(|e| format!("copy {src} -> {dst}: {e}"))
    }

    /// The bytes of one remote file, refusing anything over `max` bytes.
    pub fn cat(&self, path: &str, max: usize) -> Result<String, String> {
        let limit = (max + 1).to_string();
        let out = self
            .run(&["cat", "--count", &limit, path], None, SHORT_TIMEOUT)
            .map_err(|e| format!("cat {path}: {e}"))?;
        if out.len() > max {
            return Err(format!("{path} is larger than {max} bytes"));
        }
        Ok(out)
    }

    /// `relative path -> size` for every file under `path`.
    pub fn sizes(&self, path: &str) -> Result<BTreeMap<String, u64>, String> {
        let args = ["lsf", "-R", "--files-only", "--format", "sp", path];
        match self.run(&args, None, SHORT_TIMEOUT) {
            Ok(out) => Ok(parse_sizes(&out)),
            Err(e) if e.code == Some(EXIT_DIR_NOT_FOUND) => Ok(BTreeMap::new()),
            Err(e) => Err(format!("list {path}: {e}")),
        }
    }

    /// Remove a remote slot: its manifest first, so a half-finished removal
    /// leaves an uncommitted dir rather than a committed but gutted slot.
    pub fn remove_slot(&self, slot_path: &str) -> Result<(), String> {
        let manifest = format!("{slot_path}/manifest.json");
        self.tolerate_missing(&["deletefile", &manifest], &manifest)?;
        self.tolerate_missing(&["purge", slot_path], slot_path)
    }

    /// Run a delete; a failure counts only if `path` still exists, since
    /// backends disagree on the exit code for an already-missing path.
    fn tolerate_missing(&self, args: &[&str], path: &str) -> Result<(), String> {
        let Err(e) = self.run(args, None, SHORT_TIMEOUT) else {
            return Ok(());
        };
        match self.run(&["lsf", path], None, SHORT_TIMEOUT) {
            Err(gone) if gone.code == Some(EXIT_DIR_NOT_FOUND) => Ok(()),
            _ => Err(format!("{} {path}: {e}", args[0])),
        }
    }
}

/// The two `--filter-from` passes for [`Rclone::push_slots`]: every slot's
/// payload, then every slot's manifest.
pub fn push_filters(slots: &BTreeSet<String>) -> [String; 2] {
    let mut payloads = String::new();
    let mut manifests = String::new();
    for s in slots {
        let s = escape_glob(s);
        payloads.push_str(&format!("+ /{s}/payload/**\n"));
        manifests.push_str(&format!("+ /{s}/manifest.json\n"));
    }
    payloads.push_str("- **\n");
    manifests.push_str("- **\n");
    [payloads, manifests]
}

/// Parse `lsf --format sp` (`<size>;<path>`) lines.
pub fn parse_sizes(out: &str) -> BTreeMap<String, u64> {
    out.lines()
        .filter_map(|l| {
            let (size, path) = l.split_once(';')?;
            Some((path.to_string(), size.trim().parse().ok()?))
        })
        .collect()
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

/// A relative, `/`-separated path with no empty, `.`, `..`, `payload` or
/// `.orca-*` segment.
pub fn is_safe_slot(slot: &str) -> bool {
    !slot.is_empty()
        && slot
            .split('/')
            .all(|seg| !matches!(seg, "" | "." | ".." | "payload") && !seg.starts_with(".orca-"))
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

    const BIN: &[u8] = b"#!/bin/sh\necho rclone v1.75.1\n";

    struct Fixture {
        zip: Vec<u8>,
        zip_digest: String,
        bin_digest: String,
    }

    fn fixture() -> Fixture {
        let zip = b"fake-zip".to_vec();
        Fixture {
            zip_digest: sha256_hex(&zip),
            bin_digest: sha256_hex(BIN),
            zip,
        }
    }

    impl Fixture {
        fn pin(&self) -> Pin<'_> {
            Pin {
                arch: "amd64",
                zip: &self.zip_digest,
                bin: &self.bin_digest,
            }
        }
        fn fetch(&self) -> impl Fn(&str) -> Result<Vec<u8>, String> + '_ {
            move |url: &str| {
                if url.ends_with("SHA256SUMS") {
                    Ok(sums_for("r.zip", &self.zip_digest).into_bytes())
                } else {
                    Ok(self.zip.clone())
                }
            }
        }
    }

    fn extract_bin(_zip: &Path, member: &str, dest: &Path) -> Result<(), String> {
        assert_eq!(member, "r/rclone");
        fs::write(dest, BIN).map_err(|e| e.to_string())
    }

    fn no_files_but(dir: &Path, keep: &[&str]) -> bool {
        fs::read_dir(dir)
            .unwrap()
            .all(|e| keep.contains(&e.unwrap().file_name().to_str().unwrap()))
    }

    #[test]
    fn release_arch_maps_supported_and_rejects_others() {
        assert_eq!(release_arch("x86_64").unwrap(), "amd64");
        assert_eq!(release_arch("aarch64").unwrap(), "arm64");
        assert!(release_arch("riscv64").is_err());
        assert!(pin_for("amd64").is_some());
        assert!(pin_for("arm64").is_some());
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
        assert!(verify_download(&sums, "a.zip", &good, b"evil").is_err());
        let other = sums_for("a.zip", &"b".repeat(64));
        assert!(verify_download(&other, "a.zip", &good, bytes).is_err());
        assert!(verify_download(&sums, "b.zip", &good, bytes).is_err());
    }

    #[test]
    fn provision_installs_a_verified_binary_and_leaves_no_partials() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let bin = provision(dir.path(), "r.zip", f.pin(), &f.fetch(), &extract_bin).unwrap();
        assert_eq!(bin, dir.path().join("rclone"));
        assert_eq!(fs::read(&bin).unwrap(), BIN);
        assert!(no_files_but(dir.path(), &["rclone"]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&bin).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn provision_refuses_a_zip_checksum_mismatch_before_extracting() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let tampered = |url: &str| -> Result<Vec<u8>, String> {
            if url.ends_with("SHA256SUMS") {
                Ok(sums_for("r.zip", &f.zip_digest).into_bytes())
            } else {
                Ok(b"tampered".to_vec())
            }
        };
        let extracted = RefCell::new(false);
        let extract = |_: &Path, _: &str, _: &Path| -> Result<(), String> {
            *extracted.borrow_mut() = true;
            Ok(())
        };
        let err = provision(dir.path(), "r.zip", f.pin(), &tampered, &extract).unwrap_err();
        assert!(err.contains("sha256"), "{err}");
        assert!(!*extracted.borrow());
        assert!(!dir.path().join("rclone").exists());
    }

    #[test]
    fn provision_refuses_an_extracted_binary_that_does_not_match_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let evil = |_: &Path, _: &str, dest: &Path| -> Result<(), String> {
            fs::write(dest, b"evil").map_err(|e| e.to_string())
        };
        let err = provision(dir.path(), "r.zip", f.pin(), &f.fetch(), &evil).unwrap_err();
        assert!(err.contains("extracted rclone"), "{err}");
        assert!(no_files_but(dir.path(), &[]));
    }

    #[test]
    fn provision_leaves_nothing_when_extraction_fails() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let boom = |_: &Path, _: &str, _: &Path| -> Result<(), String> { Err("boom".into()) };
        assert!(provision(dir.path(), "r.zip", f.pin(), &f.fetch(), &boom).is_err());
        assert!(no_files_but(dir.path(), &[]));
    }

    fn resolver<'a>(
        dir: &'a Path,
        os: &'a str,
        f: &'a Fixture,
        fetch: &'a dyn Fn(&str) -> Result<Vec<u8>, String>,
        on_path: Option<&str>,
        version: &'a dyn Fn(&Path) -> Result<String, String>,
    ) -> Resolver<'a> {
        Resolver {
            dir,
            os,
            asset: "r.zip".into(),
            pin: Some(f.pin()),
            on_path: on_path.map(str::to_string),
            fetch,
            extract: &extract_bin,
            version_of: version,
        }
    }

    #[test]
    fn resolve_prefers_the_pinned_build_over_path() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let fetched = RefCell::new(0);
        let fetch = |u: &str| {
            *fetched.borrow_mut() += 1;
            f.fetch()(u)
        };
        let newer = |_: &Path| Ok("rclone v9.0.0".to_string());
        let r = resolver(
            dir.path(),
            "linux",
            &f,
            &fetch,
            Some("/usr/bin/rclone"),
            &newer,
        );
        assert_eq!(resolve_with(&r).unwrap(), dir.path().join("rclone"));
        assert_eq!(*fetched.borrow(), 2);
        // Installed and verified: no network.
        assert_eq!(resolve_with(&r).unwrap(), dir.path().join("rclone"));
        assert_eq!(*fetched.borrow(), 2);
    }

    #[test]
    fn resolve_replaces_a_tampered_installed_binary() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        fs::write(dir.path().join("rclone"), b"tampered").unwrap();
        let fetch = f.fetch();
        let v = |_: &Path| Err("unused".to_string());
        let r = resolver(dir.path(), "linux", &f, &fetch, None, &v);
        let bin = resolve_with(&r).unwrap();
        assert_eq!(fs::read(bin).unwrap(), BIN);
    }

    #[test]
    fn resolve_off_linux_uses_only_a_new_enough_absolute_path_rclone() {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture();
        let fetch = |_: &str| -> Result<Vec<u8>, String> { panic!("must not provision") };
        let newer = |_: &Path| Ok("rclone v1.76.0\n- os/version: x".to_string());
        let older = |_: &Path| Ok("rclone v1.60.1".to_string());
        let ok = resolver(dir.path(), "macos", &f, &fetch, Some("/opt/rclone"), &newer);
        assert_eq!(resolve_with(&ok).unwrap(), PathBuf::from("/opt/rclone"));
        let old = resolver(dir.path(), "macos", &f, &fetch, Some("/opt/rclone"), &older);
        assert!(resolve_with(&old).unwrap_err().contains("older"));
        let rel = resolver(dir.path(), "macos", &f, &fetch, Some("bin/rclone"), &newer);
        assert!(resolve_with(&rel).unwrap_err().contains("non-absolute"));
        let none = resolver(dir.path(), "macos", &f, &fetch, None, &newer);
        assert!(resolve_with(&none).is_err());
    }

    #[test]
    fn parse_version_reads_the_first_line() {
        assert_eq!(parse_version("rclone v1.75.1\n- os"), Some((1, 75, 1)));
        assert_eq!(parse_version("rclone v1.76.0-beta.1"), Some((1, 76, 0)));
        assert_eq!(parse_version("rclone 1.75.1"), None);
        assert_eq!(parse_version(""), None);
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
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "lsf");
        assert!(args.contains(&"--contimeout".to_string()));
        assert!(args
            .iter()
            .all(|a| !a.contains("hunter2") && !a.contains("OBSCURED")));
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

    // ── real processes, via a stub standing in for rclone ──

    #[cfg(unix)]
    fn stub(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("rclone-stub");
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    fn stubbed(dir: &Path, body: &str) -> Rclone {
        Rclone::with_obscured(stub(dir, body), "h", "u", "hunter2", "OBSC")
    }

    #[cfg(unix)]
    #[test]
    fn run_clears_the_environment_but_for_the_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let rc = stubbed(dir.path(), "env");
        let out = rc.run(&["x"], None, SHORT_TIMEOUT).unwrap();
        let keys: BTreeSet<&str> = out.lines().filter_map(|l| l.split('=').next()).collect();
        for k in &keys {
            assert!(
                ENV_PASSTHROUGH.contains(k)
                    || k.starts_with("RCLONE_")
                    // Set by the stub's own shell.
                    || ["PWD", "OLDPWD", "SHLVL", "_"].contains(k),
                "leaked env var {k}"
            );
        }
        assert!(keys.contains("RCLONE_SMB_PASS"));
    }

    #[cfg(unix)]
    #[test]
    fn run_feeds_stdin_and_scrubs_stderr_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let rc = stubbed(dir.path(), "cat >&2; echo pass=OBSC >&2; exit 7");
        let err = rc
            .run(&["x"], Some("hunter2 typed"), SHORT_TIMEOUT)
            .unwrap_err();
        assert_eq!(err.code, Some(7));
        assert!(err.stderr.contains("typed"), "{}", err.stderr);
        assert!(!err.stderr.contains("hunter2") && !err.stderr.contains("OBSC"));
    }

    #[cfg(unix)]
    #[test]
    fn run_kills_and_reaps_a_hung_child() {
        let dir = tempfile::tempdir().unwrap();
        let rc = stubbed(dir.path(), "exec sleep 30");
        let t = Instant::now();
        let err = rc
            .run(&["x"], None, Duration::from_millis(200))
            .unwrap_err();
        assert!(err.stderr.contains("timed out"), "{}", err.stderr);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn run_honours_an_expired_overall_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let rc = stubbed(dir.path(), "exit 0").with_deadline(Instant::now());
        let err = rc.run(&["x"], None, SHORT_TIMEOUT).unwrap_err();
        assert!(err.stderr.contains("deadline"));
    }

    #[cfg(unix)]
    #[test]
    fn missing_remote_dir_lists_empty_but_other_failures_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stubbed(dir.path(), "exit 3")
            .list_slots(":smb:s/x")
            .unwrap()
            .is_empty());
        assert!(stubbed(dir.path(), "exit 3")
            .sizes(":smb:s/x")
            .unwrap()
            .is_empty());
        assert!(stubbed(dir.path(), "exit 1")
            .list_slots(":smb:s/x")
            .is_err());
        let rc = stubbed(dir.path(), "echo 'a/1/manifest.json'");
        assert_eq!(
            rc.list_slots(":smb:s").unwrap(),
            BTreeSet::from(["a/1".into()])
        );
    }

    #[cfg(unix)]
    #[test]
    fn remove_slot_deletes_the_manifest_before_purging() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log");
        let rc = stubbed(
            dir.path(),
            &format!("echo \"$1 ${{10}}\" >> {}", log.display()),
        );
        rc.remove_slot(":smb:s/g/1").unwrap();
        let calls = fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(
            lines,
            vec!["deletefile :smb:s/g/1/manifest.json", "purge :smb:s/g/1"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn remove_slot_tolerates_an_already_missing_path_only() {
        let dir = tempfile::tempdir().unwrap();
        // Delete fails, and lsf confirms the path is gone.
        let gone = stubbed(dir.path(), "[ \"$1\" = lsf ] && exit 3; exit 1");
        assert!(gone.remove_slot(":smb:s/g/1").is_ok());
        let present = stubbed(dir.path(), "[ \"$1\" = lsf ] && exit 0; exit 1");
        assert!(present.remove_slot(":smb:s/g/1").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cat_refuses_oversized_output() {
        let dir = tempfile::tempdir().unwrap();
        let rc = stubbed(dir.path(), "printf 0123456789");
        assert_eq!(rc.cat("p", 10).unwrap(), "0123456789");
        assert!(rc.cat("p", 9).is_err());
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
    fn push_filters_send_payloads_then_manifests() {
        let slots: BTreeSet<String> = ["g/a/1".to_string(), "g/[b]/2".to_string()].into();
        let [payloads, manifests] = push_filters(&slots);
        assert_eq!(
            payloads,
            "+ /g/\\[b\\]/2/payload/**\n+ /g/a/1/payload/**\n- **\n"
        );
        assert_eq!(
            manifests,
            "+ /g/\\[b\\]/2/manifest.json\n+ /g/a/1/manifest.json\n- **\n"
        );
    }

    #[test]
    fn parse_sizes_splits_on_the_first_separator() {
        let m = parse_sizes("12;payload/a\n3;payload/b;c\nbad\n");
        assert_eq!(m.get("payload/a"), Some(&12));
        assert_eq!(m.get("payload/b;c"), Some(&3));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn parse_manifest_listing_keeps_slots_and_drops_unsafe() {
        let out = "\
game-saves/bragi/20261004-030000/manifest.json
game-saves/bragi/20261004-030000/payload/manifest.json
manifest.json
../escape/manifest.json
a//b/manifest.json
.orca-incoming/x/manifest.json
game-saves/x/notes.txt
";
        let slots = parse_manifest_listing(out);
        assert_eq!(
            slots.into_iter().collect::<Vec<_>>(),
            vec!["game-saves/bragi/20261004-030000".to_string()]
        );
    }
}
