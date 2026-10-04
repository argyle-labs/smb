//! `smb` backup TARGET: the generic backup store writes into a local stage dir,
//! and the stage is reconciled with an SMB share over rclone.
//!
//! A target instance `<name>` is configured by the `backup`/`target:smb:<name>`
//! config row (as core's `local` target reads `target:local:<name>`):
//!
//! ```json
//! {"host":"10.0.0.10","share":"backups","path":"game-saves","user":"skey",
//!  "passwordSecret":"smb.<name>.password","stage":"/optional/absolute/dir"}
//! ```
//!
//! ## Reconcile, and why `sync` is safe on its own
//!
//! Several hosts may share one remote (game saves are meant to), and the host
//! calls `refresh` only before list/restore — a `backup.run` goes open → write
//! → prune → `sync` with no refresh. A blind `rclone sync stage -> remote` from
//! a stale stage would delete every slot another host added since. So both
//! `sync` and `refresh` run the same slot-level three-way [`reconcile`]: the
//! stage keeps a baseline of the slots last confirmed on BOTH sides (bound to
//! this target's backing key and name), and
//! * a slot in the baseline but gone from the stage was pruned here → remove it
//!   remotely;
//! * a slot in the baseline but gone from the remote was pruned elsewhere →
//!   drop it from the stage;
//! * a stage slot not in the baseline is new here → push it; one whose path
//!   already exists remotely is adopted only if its manifest (bar the host-local
//!   `path`) and every payload size match, else reported as a conflict;
//! * a remote slot absent here is pulled. Slots already held locally are never
//!   re-copied, so a tampered remote cannot rewrite a local backup.
//!
//! Nothing outside the baseline is ever deleted, deletions per pass are capped,
//! and nested slots, invalid manifests and same-id conflicts are left untouched
//! and reported. Every pulled manifest is validated and its `path` rewritten to
//! this host's copy before it becomes visible, since core trusts `path` for
//! prune and restore. `bisync` was not used: it reconciles files, not slots, so
//! it would push a half-written slot, cannot tell a same-id collision from an
//! update, and needs a `--resync` bootstrap plus its own lock/state recovery.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use plugin_toolkit::abi::{BackendDef, DbOp, DbRow, DbValue};
use plugin_toolkit::backend_def::backup_target_backend_def;
use plugin_toolkit::backup::{dispatch_target_op, BackupTargetPlugin};
use plugin_toolkit::contract::backup::BackupRecord;
use plugin_toolkit::path::expand_tilde;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use crate::rclone::{self, Rclone, MAX_MANIFEST_BYTES};

/// The backup target kind this plugin contributes.
pub const TARGET_KIND: &str = "smb";
/// Bridge invoke-prefix for the `smb` backup TARGET.
const INVOKE_PREFIX: &str = "smb.__backup_target";

/// Stage lock file. Protocol: open `<stage>/.orca-stage.lock` (create if
/// absent, never delete it) and hold an exclusive advisory `flock(2)` lock on
/// it (`std::fs::File::lock`) for the whole of any stage mutation: a reconcile
/// here, a slot write or prune in core. Closing the file releases it.
pub const STAGE_LOCK: &str = ".orca-stage.lock";
/// Written into a stage on creation; a non-empty dir without it is refused so a
/// misconfigured `stage` can never adopt (and later prune) unrelated files.
pub const STAGE_MARKER: &str = ".orca-smb-stage";
/// Slots last confirmed on both sides. Lives in the stage itself so a wiped
/// stage also forgets it and starts fresh.
const BASELINE: &str = ".orca-smb-baseline.json";
const INCOMING: &str = ".orca-incoming";
const TRASH: &str = ".orca-trash";
const MANIFEST: &str = "manifest.json";
const PAYLOAD: &str = "payload";

const LOCK_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RECONCILE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

/// The `backup`/`target:smb:<name>` config row shape.
#[orca_struct]
#[orca(rename_all = "camelCase")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbTargetConfig {
    pub host: String,
    pub share: String,
    /// Directory within the share. Empty = the share root.
    #[orca(default)]
    pub path: String,
    pub user: String,
    /// Secret holding the password, within the plugin's own `smb.` namespace.
    /// Defaults to `smb.<name>.password`.
    #[orca(default)]
    pub password_secret: Option<String>,
    /// Absolute local stage dir. Defaults to
    /// `<orca state dir>/backup-stage/smb-<name>`.
    #[orca(default)]
    pub stage: Option<String>,
}

/// A bare hostname or IP address — never a URL, port or `user@host`.
pub fn is_valid_host(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

impl SmbTargetConfig {
    pub fn parse(json: &str) -> Result<Self, String> {
        let mut cfg: Self =
            serde_json::from_str(json).map_err(|e| format!("invalid smb target config: {e}"))?;
        cfg.host = cfg.host.trim().to_string();
        cfg.share = cfg.share.trim().trim_matches('/').to_string();
        cfg.path = cfg.path.trim().trim_matches('/').to_string();
        if !is_valid_host(&cfg.host) {
            return Err(format!(
                "smb target config: `host` must be a hostname or IP, got {:?}",
                cfg.host
            ));
        }
        if cfg.share.is_empty() || cfg.share.contains(['/', '\\']) {
            return Err("smb target config: `share` must be a single share name".into());
        }
        if cfg.user.trim().is_empty() {
            return Err("smb target config: `user` is required".into());
        }
        if !cfg.path.is_empty() && !rclone::is_safe_slot(&cfg.path) {
            return Err(format!("smb target config: bad `path` {:?}", cfg.path));
        }
        if let Some(s) = cfg.password_secret.as_deref().map(str::trim) {
            if !s.is_empty() && !s.starts_with("smb.") {
                return Err("smb target config: `passwordSecret` must be an `smb.` secret".into());
            }
        }
        Ok(cfg)
    }

    pub fn password_ref(&self, name: &str) -> String {
        self.password_secret
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| plugin_toolkit::secrets::scoped_name(TARGET_KIND, name, "password"))
    }

    /// `smb://<host>/<share>[/<path>]` — identical on every host pointing at the
    /// same folder, so fleet collision detection sees a shared remote as shared.
    pub fn backing_key(&self) -> String {
        if self.path.is_empty() {
            format!("smb://{}/{}", self.host, self.share)
        } else {
            format!("smb://{}/{}/{}", self.host, self.share, self.path)
        }
    }

    pub fn remote_root(&self) -> String {
        rclone::remote_root(&self.share, &self.path)
    }

    pub fn stage_dir(&self, name: &str, state_dir: &Path) -> Result<PathBuf, String> {
        let dir = match self
            .stage
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => PathBuf::from(expand_tilde(s)),
            None => state_dir
                .join("backup-stage")
                .join(format!("smb-{}", name.replace(['/', '\\'], "_"))),
        };
        if !dir.is_absolute() || dir.components().any(|c| c == Component::ParentDir) {
            return Err(format!(
                "smb target `{name}`: stage {} must be an absolute path without `..`",
                dir.display()
            ));
        }
        Ok(dir)
    }
}

/// The config-row name for an smb target instance: `target:smb:<name>`.
pub fn row_name(name: &str) -> String {
    format!("target:{TARGET_KIND}:{name}")
}

fn text(row: &DbRow, col: &str) -> String {
    match row.get(col) {
        Some(DbValue::Text(s)) => s.clone(),
        _ => String::new(),
    }
}

fn is_replica(r: &DbRow) -> bool {
    match r.get("is_replica") {
        Some(DbValue::Int(n)) => *n != 0,
        Some(DbValue::Bool(b)) => *b,
        _ => false,
    }
}

/// Pick the `backup` row out of every `config_rows` row with this name, with
/// core's precedence: an owned row over a replica, then newest, then lowest id.
pub fn pick_config_json(rows: &[DbRow]) -> Option<String> {
    rows.iter()
        .filter(|r| text(r, "noun") == "backup")
        .min_by(|a, b| {
            is_replica(a)
                .cmp(&is_replica(b))
                .then_with(|| text(b, "updated_at").cmp(&text(a, "updated_at")))
                .then_with(|| text(a, "id").cmp(&text(b, "id")))
        })
        .map(|r| text(r, "json"))
}

fn config_rows(op: DbOp) -> Result<Vec<DbRow>, String> {
    plugin_toolkit::runtime::db_op(&op)
        .map(|r| r.rows)
        .map_err(|e| format!("read backup config: {e:#}"))
}

fn load_config(name: &str) -> Result<SmbTargetConfig, String> {
    let row = row_name(name);
    let rows = config_rows(DbOp::Get {
        namespace: String::new(),
        table: "config_rows".into(),
        key_col: "name".into(),
        key: row.clone(),
    })?;
    let json = pick_config_json(&rows)
        .ok_or_else(|| format!("no backup/{row} config row for smb target `{name}`"))?;
    SmbTargetConfig::parse(&json)
}

/// Stage dirs of this host's other smb targets, for the overlap check.
fn other_stages(name: &str, state_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let rows = config_rows(DbOp::List {
        namespace: String::new(),
        table: "config_rows".into(),
    })?;
    let prefix = row_name("");
    Ok(rows
        .iter()
        .filter(|r| text(r, "noun") == "backup" && !is_replica(r))
        .filter_map(|r| {
            let other = text(r, "name").strip_prefix(&prefix)?.to_string();
            (other != name).then_some(())?;
            SmbTargetConfig::parse(&text(r, "json"))
                .ok()?
                .stage_dir(&other, state_dir)
                .ok()
        })
        .collect())
}

fn state_dir() -> Result<PathBuf, String> {
    plugin_toolkit::contract::config::state_dir().map_err(|e| format!("{e:#}"))
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Check `stage` is safe to own, then create it (with its marker) if needed.
pub(crate) fn prepare_stage(
    stage: &Path,
    state_dir: &Path,
    others: &[PathBuf],
) -> Result<(), String> {
    let local_store = state_dir.join("backups");
    if overlaps(stage, &local_store) {
        return Err(format!(
            "stage {} overlaps the local target's store {}, which would list and prune its slots",
            stage.display(),
            local_store.display()
        ));
    }
    if let Some(o) = others.iter().find(|o| overlaps(stage, o)) {
        return Err(format!(
            "stage {} overlaps another smb target's stage {}",
            stage.display(),
            o.display()
        ));
    }
    let marker = stage.join(STAGE_MARKER);
    if marker.is_file() {
        return Ok(());
    }
    match fs::read_dir(stage) {
        Ok(mut rd) => {
            if rd.next().is_some() {
                return Err(format!(
                    "stage {} is a non-empty directory not created by orca (no {STAGE_MARKER})",
                    stage.display()
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(stage).map_err(|e| format!("create {}: {e}", stage.display()))?
        }
        Err(e) => return Err(format!("read {}: {e}", stage.display())),
    }
    write_atomic(&marker, b"")
}

/// The exclusive stage lock (see [`STAGE_LOCK`]).
pub(crate) struct StageLock(fs::File);

impl StageLock {
    pub(crate) fn acquire(stage: &Path, timeout: Duration) -> Result<Self, String> {
        let path = stage.join(STAGE_LOCK);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let deadline = Instant::now() + timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self(file)),
                Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(format!(
                        "stage {} is locked by another writer",
                        stage.display()
                    ))
                }
                Err(fs::TryLockError::Error(e)) => {
                    return Err(format!("lock {}: {e}", path.display()))
                }
            }
        }
    }
}

impl Drop for StageLock {
    fn drop(&mut self) {
        drop(self.0.unlock());
    }
}

// ── Stage files ───────────────────────────────────────────────────────────

fn fsync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        drop(d.sync_all());
    }
}

fn unique() -> String {
    format!("{}.{}", std::process::id(), plugin_toolkit::id::new())
}

/// Write via a same-dir temp file, fsync, rename, then fsync the dir.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".orca-tmp.{}", unique()));
    let written = fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = written {
        drop(fs::remove_file(&tmp));
        return Err(format!("write {}: {e}", path.display()));
    }
    fsync_dir(dir);
    Ok(())
}

/// What the stage holds: complete slots, and slots still being written.
#[derive(Debug, Default)]
pub(crate) struct LocalSlots {
    pub committed: BTreeSet<String>,
    pub in_progress: BTreeSet<String>,
}

/// Walk the stage like the generic store does: a dir with `manifest.json` is a
/// committed slot, one with only `payload/` is in progress, no walk enters a
/// payload, and the plugin's own `.orca-*` dirs are skipped.
pub(crate) fn local_slots(stage: &Path) -> Result<LocalSlots, String> {
    let mut out = LocalSlots::default();
    let mut stack = vec![stage.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", dir.display())),
        };
        let (mut manifest, mut payload) = (false, false);
        for entry in rd {
            let entry = entry.map_err(|e| format!("read {}: {e}", dir.display()))?;
            let ft = entry
                .file_type()
                .map_err(|e| format!("stat {}: {e}", entry.path().display()))?;
            let name = entry.file_name();
            if ft.is_dir() {
                if name == PAYLOAD {
                    payload = true;
                } else if !name.to_string_lossy().starts_with(".orca-") {
                    stack.push(entry.path());
                }
            } else if name == MANIFEST {
                manifest = true;
            }
        }
        let Some(rel) = rel_slot(stage, &dir) else {
            continue;
        };
        if manifest {
            out.committed.insert(rel);
        } else if payload {
            out.in_progress.insert(rel);
        }
    }
    Ok(out)
}

fn rel_slot(stage: &Path, dir: &Path) -> Option<String> {
    let rel = dir.strip_prefix(stage).ok()?;
    let parts: Option<Vec<&str>> = rel.components().map(|c| c.as_os_str().to_str()).collect();
    let slot = parts?.join("/");
    rclone::is_safe_slot(&slot).then_some(slot)
}

/// The baseline is only meaningful for the remote it was taken against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub backing_key: String,
    pub target: String,
}

#[orca_struct]
#[orca(rename_all = "camelCase")]
struct BaselineFile {
    backing_key: String,
    target: String,
    slots: BTreeSet<String>,
}

/// The baseline for `binding`. Missing, unparsable or bound to another remote
/// reads as empty, which never deletes anything.
fn read_baseline(stage: &Path, binding: &Binding) -> BTreeSet<String> {
    fs::read_to_string(stage.join(BASELINE))
        .ok()
        .and_then(|s| serde_json::from_str::<BaselineFile>(&s).ok())
        .filter(|b| b.backing_key == binding.backing_key && b.target == binding.target)
        .map(|b| b.slots)
        .unwrap_or_default()
}

fn write_baseline(stage: &Path, binding: &Binding, slots: &BTreeSet<String>) -> Result<(), String> {
    let file = BaselineFile {
        backing_key: binding.backing_key.clone(),
        target: binding.target.clone(),
        slots: slots.clone(),
    };
    let json = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
    write_atomic(&stage.join(BASELINE), &json)
}

// ── Manifests ─────────────────────────────────────────────────────────────

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && !matches!(id, "." | "..")
        && !id.starts_with(".orca-")
        && !id.contains(['/', '\\', '\0'])
}

/// Parse a slot manifest and check its id names the slot dir it sits in.
pub(crate) fn validate_manifest(json: &str, slot: &str) -> Result<BackupRecord, String> {
    let rec: BackupRecord =
        serde_json::from_str(json).map_err(|e| format!("unparsable manifest: {e}"))?;
    if !is_valid_id(&rec.id) {
        return Err(format!("manifest id {:?} is not a valid slot id", rec.id));
    }
    let leaf = slot.rsplit('/').next().unwrap_or(slot);
    if rec.id != leaf {
        return Err(format!(
            "manifest id {:?} does not match its slot dir {leaf:?}",
            rec.id
        ));
    }
    Ok(rec)
}

/// A pulled manifest, validated, with `path` pointing at this host's payload
/// copy: core prunes and restores by `path`, so a foreign or crafted value must
/// never survive the pull.
pub(crate) fn rewrite_manifest(json: &str, slot: &str, payload: &Path) -> Result<String, String> {
    let mut rec = validate_manifest(json, slot)?;
    rec.path = payload.to_string_lossy().into_owned();
    rec.system = String::new();
    serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())
}

fn read_local_manifest(stage: &Path, slot: &str) -> Result<String, String> {
    let path = stage.join(slot).join(MANIFEST);
    let len = fs::metadata(&path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if len > MAX_MANIFEST_BYTES as u64 {
        return Err(format!(
            "{} is larger than {MAX_MANIFEST_BYTES} bytes",
            path.display()
        ));
    }
    fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// `payload/<rel> -> size` for a local slot.
fn local_payload_sizes(slot_dir: &Path) -> Result<BTreeMap<String, u64>, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![slot_dir.join(PAYLOAD)];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", dir.display())),
        };
        for entry in rd {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if let Ok(rel) = entry.path().strip_prefix(slot_dir) {
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.insert(parts.join("/"), meta.len());
            }
        }
    }
    Ok(out)
}

/// Whether a remote slot is the very backup this stage holds under the same
/// path. SMB exposes no hashes, so this compares the manifest (identity,
/// timestamp, size, file count, checksum — everything but the host-local
/// `path`) and every payload file's size. Any doubt reads as "different".
fn same_slot(stage: &Path, slot: &str, remote: &dyn SlotRemote) -> bool {
    let local = read_local_manifest(stage, slot).and_then(|m| validate_manifest(&m, slot));
    let theirs = remote
        .manifest(slot)
        .and_then(|m| validate_manifest(&m, slot));
    let (Ok(mut local), Ok(mut theirs)) = (local, theirs) else {
        return false;
    };
    local.path.clear();
    theirs.path.clear();
    local.system.clear();
    theirs.system.clear();
    if local != theirs {
        return false;
    }
    let (Ok(ours), Ok(remote_sizes)) = (local_payload_sizes(&stage.join(slot)), remote.sizes(slot))
    else {
        return false;
    };
    let remote_payload: BTreeMap<String, u64> = remote_sizes
        .into_iter()
        .filter(|(k, _)| k.starts_with("payload/"))
        .collect();
    ours == remote_payload
}

// ── Reconcile ─────────────────────────────────────────────────────────────

/// The slot-level decisions for one reconcile.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Pruned here since the last reconcile.
    pub remote_delete: BTreeSet<String>,
    /// Pruned by another host since the last reconcile.
    pub local_delete: BTreeSet<String>,
    /// New here and absent remotely.
    pub push: BTreeSet<String>,
    /// New here but the same path already exists remotely.
    pub check: BTreeSet<String>,
}

pub(crate) fn plan(
    local: &BTreeSet<String>,
    baseline: &BTreeSet<String>,
    remote: &BTreeSet<String>,
) -> Result<Plan, String> {
    // A side that held synced slots and now lists none is far likelier to be a
    // misconfigured path or a wiped disk than a prune of everything; mirroring
    // it would erase the surviving copy.
    if !baseline.is_empty() && remote.is_empty() {
        return Err(format!(
            "remote lists no backups but {} were synced before; refusing to mirror an empty remote",
            baseline.len()
        ));
    }
    if !baseline.is_empty() && local.is_empty() {
        return Err(format!(
            "stage lists no backups but {} were synced before; refusing to purge the remote",
            baseline.len()
        ));
    }
    let new_here: BTreeSet<String> = local.difference(baseline).cloned().collect();
    let p = Plan {
        remote_delete: baseline
            .difference(local)
            .filter(|s| remote.contains(*s))
            .cloned()
            .collect(),
        local_delete: baseline
            .intersection(local)
            .filter(|s| !remote.contains(*s))
            .cloned()
            .collect(),
        push: new_here.difference(remote).cloned().collect(),
        check: new_here.intersection(remote).cloned().collect(),
    };
    let deletes = p.remote_delete.len() + p.local_delete.len();
    let cap = 3.max(baseline.len() / 4);
    if deletes > cap {
        return Err(format!(
            "would delete {deletes} of {} synced slots in one pass (cap {cap}); refusing — \
             if a retention change caused this, raise it gradually",
            baseline.len()
        ));
    }
    Ok(p)
}

/// Slots that are an ancestor or descendant of another slot. Acting on either
/// would delete or overwrite the other, so both are left alone.
pub(crate) fn nested_slots(slots: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in slots {
        let prefix = format!("{s}/");
        for d in slots.range(prefix.clone()..) {
            if !d.starts_with(&prefix) {
                break;
            }
            out.insert(s.clone());
            out.insert(d.clone());
        }
    }
    out
}

/// The remote operations a reconcile needs, so the safety logic is testable
/// without an SMB server.
pub(crate) trait SlotRemote {
    fn list(&self) -> Result<BTreeSet<String>, String>;
    /// Payloads first, manifests last.
    fn push(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String>;
    /// Payloads only, into `dest/<slot>/payload`, never overwriting.
    fn pull_payloads(&self, dest: &Path, slots: &BTreeSet<String>) -> Result<(), String>;
    fn manifest(&self, slot: &str) -> Result<String, String>;
    /// `relative path -> size` for every file under the slot.
    fn sizes(&self, slot: &str) -> Result<BTreeMap<String, u64>, String>;
    /// Manifest first, then the rest.
    fn remove(&self, slot: &str) -> Result<(), String>;
}

struct RcloneRemote {
    rclone: Rclone,
    root: String,
}

impl RcloneRemote {
    fn at(&self, slot: &str) -> String {
        format!("{}/{slot}", self.root)
    }
}

impl SlotRemote for RcloneRemote {
    fn list(&self) -> Result<BTreeSet<String>, String> {
        self.rclone.list_slots(&self.root)
    }
    fn push(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
        self.rclone
            .push_slots(&stage.to_string_lossy(), &self.root, slots)
    }
    fn pull_payloads(&self, dest: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
        self.rclone
            .pull_payloads(&self.root, &dest.to_string_lossy(), slots)
    }
    fn manifest(&self, slot: &str) -> Result<String, String> {
        self.rclone
            .cat(&format!("{}/{MANIFEST}", self.at(slot)), MAX_MANIFEST_BYTES)
    }
    fn sizes(&self, slot: &str) -> Result<BTreeMap<String, u64>, String> {
        self.rclone.sizes(&self.at(slot))
    }
    fn remove(&self, slot: &str) -> Result<(), String> {
        self.rclone.remove_slot(&self.at(slot))
    }
}

/// Drop one local slot: the manifest is renamed away first (the slot stops
/// being committed atomically), then its payload. Nothing else in the slot dir
/// is touched; the dir itself goes only if that leaves it empty.
fn delete_local_slot(stage: &Path, slot: &str) -> Result<(), String> {
    let dir = stage.join(slot);
    let trash = stage.join(TRASH);
    fs::create_dir_all(&trash).map_err(|e| format!("create {}: {e}", trash.display()))?;
    let tag = unique();
    let manifest = trash.join(format!("{tag}.{MANIFEST}"));
    fs::rename(dir.join(MANIFEST), &manifest)
        .map_err(|e| format!("uncommit {}: {e}", dir.display()))?;
    let payload = trash.join(format!("{tag}.{PAYLOAD}"));
    if dir.join(PAYLOAD).is_dir() {
        fs::rename(dir.join(PAYLOAD), &payload)
            .map_err(|e| format!("remove {}: {e}", dir.join(PAYLOAD).display()))?;
        fs::remove_dir_all(&payload).map_err(|e| format!("remove {}: {e}", payload.display()))?;
    }
    fs::remove_file(&manifest).map_err(|e| format!("remove {}: {e}", manifest.display()))?;
    drop(fs::remove_dir(&dir));
    Ok(())
}

/// Pull `slots` into the stage. Each manifest is fetched and validated before
/// any payload moves; payloads land in a private incoming dir, and a slot
/// appears in the stage only once its payload is in place and its rewritten
/// manifest is written last. Returns the slots rejected for bad manifests.
fn pull_into(
    stage: &Path,
    remote: &dyn SlotRemote,
    slots: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let mut rejected = Vec::new();
    let mut valid = BTreeMap::new();
    for slot in slots {
        let payload = stage.join(slot).join(PAYLOAD);
        match remote
            .manifest(slot)
            .and_then(|m| rewrite_manifest(&m, slot, &payload))
        {
            Ok(json) => {
                valid.insert(slot.clone(), json);
            }
            Err(e) => rejected.push(format!("{slot}: {e}")),
        }
    }
    if valid.is_empty() {
        return Ok(rejected);
    }
    let incoming = stage.join(INCOMING);
    drop(fs::remove_dir_all(&incoming));
    fs::create_dir_all(&incoming).map_err(|e| format!("create {}: {e}", incoming.display()))?;
    let keys: BTreeSet<String> = valid.keys().cloned().collect();
    let result = remote.pull_payloads(&incoming, &keys).and_then(|()| {
        for (slot, json) in &valid {
            install_pulled(stage, &incoming, slot, json)?;
        }
        Ok(())
    });
    drop(fs::remove_dir_all(&incoming));
    result.map(|()| rejected)
}

fn install_pulled(stage: &Path, incoming: &Path, slot: &str, json: &str) -> Result<(), String> {
    let dst = stage.join(slot);
    if dst.exists() {
        // Became a local slot (e.g. a write in progress) since listing.
        return Ok(());
    }
    fs::create_dir_all(&dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let src = incoming.join(slot).join(PAYLOAD);
    if src.is_dir() {
        fs::rename(&src, dst.join(PAYLOAD))
    } else {
        fs::create_dir(dst.join(PAYLOAD))
    }
    .map_err(|e| format!("place {}: {e}", dst.display()))?;
    write_atomic(&dst.join(MANIFEST), json.as_bytes())
}

fn minus(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    a.difference(b).cloned().collect()
}

/// What one reconcile did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub pushed: usize,
    pub purged: usize,
    pub dropped: usize,
    pub pulled: usize,
}

/// Three-way, slot-level reconcile of `stage` with `remote` (see module docs).
/// Everything safe is done even when some slots are refused; the refusals come
/// back as the error.
pub(crate) fn reconcile(
    stage: &Path,
    binding: &Binding,
    remote: &dyn SlotRemote,
) -> Result<Outcome, String> {
    let _lock = StageLock::acquire(stage, LOCK_TIMEOUT)?;
    let mut problems = Vec::new();

    let local = local_slots(stage)?;
    let baseline = read_baseline(stage, binding);
    let remote_all = remote.list()?;

    let everything: BTreeSet<String> = local
        .committed
        .iter()
        .chain(&local.in_progress)
        .chain(&remote_all)
        .cloned()
        .collect();
    let mut excluded = nested_slots(&everything);
    if !excluded.is_empty() {
        problems.push(format!(
            "nested slots left untouched: {}",
            excluded.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let candidates: Vec<String> = local.committed.difference(&excluded).cloned().collect();
    for slot in &candidates {
        if let Err(e) = read_local_manifest(stage, slot).and_then(|m| validate_manifest(&m, slot)) {
            problems.push(format!("local slot {slot} not synced: {e}"));
            excluded.insert(slot.clone());
        }
    }
    let p = plan(
        &minus(&local.committed, &excluded),
        &minus(&baseline, &excluded),
        &minus(&remote_all, &excluded),
    )?;

    for slot in &p.remote_delete {
        remote.remove(slot)?;
    }
    let conflicts: BTreeSet<String> = p
        .check
        .iter()
        .filter(|s| !same_slot(stage, s, remote))
        .cloned()
        .collect();
    if !conflicts.is_empty() {
        problems.push(format!(
            "slot(s) already exist on the remote with different contents (same backup id \
             written by another host); kept local copies, not overwritten: {}",
            conflicts.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    excluded.extend(conflicts);
    if !p.push.is_empty() {
        remote.push(stage, &p.push)?;
    }
    for slot in &p.local_delete {
        delete_local_slot(stage, slot)?;
    }

    let remote_now = minus(&remote.list()?, &excluded);
    let here = local_slots(stage)?;
    let pull: BTreeSet<String> = remote_now
        .iter()
        .filter(|s| !here.committed.contains(*s) && !here.in_progress.contains(*s))
        .cloned()
        .collect();
    match pull_into(stage, remote, &pull) {
        Ok(rejected) => problems.extend(
            rejected
                .into_iter()
                .map(|r| format!("remote slot not pulled: {r}")),
        ),
        Err(e) => problems.push(e),
    }
    // Only slots present on both sides enter the baseline: one listed remotely
    // but not (yet) pulled must never later read as "pruned here".
    let synced: BTreeSet<String> = minus(&local_slots(stage)?.committed, &excluded)
        .intersection(&remote_now)
        .cloned()
        .collect();
    write_baseline(stage, binding, &synced)?;

    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    Ok(Outcome {
        pushed: p.push.len(),
        purged: p.remote_delete.len(),
        dropped: p.local_delete.len(),
        pulled: pull.len(),
    })
}

// ── Target ────────────────────────────────────────────────────────────────

/// The `smb` backup target.
#[derive(Debug, Default)]
pub struct SmbBackupTarget;

/// Load `name`'s config and make sure its stage is safe and present.
fn open_stage(name: &str) -> Result<(SmbTargetConfig, PathBuf), String> {
    let cfg = load_config(name)?;
    let state = state_dir()?;
    let stage = cfg.stage_dir(name, &state)?;
    prepare_stage(&stage, &state, &other_stages(name, &state)?)?;
    Ok((cfg, stage))
}

impl SmbBackupTarget {
    fn reconcile_named(&self, name: &str) -> Result<(), String> {
        let (cfg, stage) = open_stage(name)?;
        let password = plugin_toolkit::secrets::get_required(&cfg.password_ref(name))
            .map_err(|e| format!("smb target `{name}`: {e:#}"))?;
        let deadline = Instant::now() + RECONCILE_TIMEOUT;
        let remote = RcloneRemote {
            rclone: Rclone::connect(rclone::resolve()?, &cfg.host, &cfg.user, &password)?
                .with_deadline(deadline),
            root: cfg.remote_root(),
        };
        let binding = Binding {
            backing_key: cfg.backing_key(),
            target: name.to_string(),
        };
        let out = reconcile(&stage, &binding, &remote)
            .map_err(|e| format!("smb target `{name}`: {e}"))?;
        tracing::info!(
            "[backup:smb] {name}: pushed {}, purged {}, dropped {}, pulled {}",
            out.pushed,
            out.purged,
            out.dropped,
            out.pulled
        );
        Ok(())
    }
}

impl BackupTargetPlugin for SmbBackupTarget {
    fn kind(&self) -> &str {
        TARGET_KIND
    }

    fn title(&self) -> String {
        "SMB share".to_string()
    }

    fn open(&self, name: &str) -> Result<String, String> {
        let (_, stage) = open_stage(name)?;
        rclone::resolve()?;
        Ok(stage.to_string_lossy().into_owned())
    }

    fn sync(&self, name: &str) -> Result<(), String> {
        self.reconcile_named(name)
    }

    fn refresh(&self, name: &str) -> Result<(), String> {
        self.reconcile_named(name)
    }

    /// Shared by design when several hosts point at one folder (`game-saves`
    /// on bragi and hemlock), which is what collision detection should see.
    fn backing_key(&self, name: &str) -> Result<String, String> {
        Ok(load_config(name)?.backing_key())
    }
}

/// Backend descriptor for the `smb` backup TARGET. Registered on the `Plugin`
/// builder via `.backend(backend_def(), Box::new(dispatcher))`.
pub fn backend_def() -> BackendDef {
    backup_target_backend_def(TARGET_KIND, INVOKE_PREFIX)
}

/// Escape-hatch dispatcher for the `smb.__backup_target.*` bridge calls;
/// `None` for anything else so the builder falls through.
pub fn dispatcher(tool: &str, args: Value) -> Option<Result<Value, Value>> {
    let op = tool
        .strip_prefix(INVOKE_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    Some(dispatch_target_op(&SmbBackupTarget, op, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ── config ──

    #[test]
    fn config_parses_full_and_defaults() {
        let cfg = SmbTargetConfig::parse(
            r#"{"host":"10.0.0.10","share":" backups/ ","path":"/game-saves/","user":"skey",
                "passwordSecret":"smb.saves.password","stage":"/var/stage"}"#,
        )
        .unwrap();
        assert_eq!(cfg.host, "10.0.0.10");
        assert_eq!(cfg.share, "backups");
        assert_eq!(cfg.path, "game-saves");
        assert_eq!(cfg.password_ref("x"), "smb.saves.password");
        assert_eq!(
            cfg.stage_dir("x", Path::new("/s")).unwrap(),
            PathBuf::from("/var/stage")
        );

        let min = SmbTargetConfig::parse(r#"{"host":"h","share":"backups","user":"u"}"#).unwrap();
        assert_eq!(min.path, "");
        assert_eq!(min.password_ref("saves"), "smb.saves.password");
        assert_eq!(
            min.stage_dir("saves", Path::new("/home/u/.orca")).unwrap(),
            PathBuf::from("/home/u/.orca/backup-stage/smb-saves")
        );
    }

    #[test]
    fn config_rejects_missing_or_unsafe_fields() {
        for bad in [
            r#"{"share":"s","user":"u"}"#,
            r#"{"host":" ","share":"s","user":"u"}"#,
            r#"{"host":"h","share":"","user":"u"}"#,
            r#"{"host":"h","share":" / ","user":"u"}"#,
            r#"{"host":"h","share":"s"}"#,
            r#"{"host":"h","share":"a/b","user":"u"}"#,
            r#"{"host":"h","share":"s","user":"u","path":"a/../b"}"#,
            r#"{"host":"h","share":"s","user":"u","path":"a//b"}"#,
            r#"{"host":"h","share":"s","user":"u","path":"a/.orca-x"}"#,
            r#"{"host":"h","share":"s","user":"u","passwordSecret":"proxmox.root.token"}"#,
            r#"{"host":"u@h","share":"s","user":"u"}"#,
            r#"{"host":"smb://h","share":"s","user":"u"}"#,
            r#"{"host":"h:445","share":"s","user":"u"}"#,
            r#"{"host":"h/x","share":"s","user":"u"}"#,
            r#"{"host":"-h","share":"s","user":"u"}"#,
        ] {
            assert!(SmbTargetConfig::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_accepts_names_and_addresses() {
        for ok in [
            "willow",
            "nas.lan",
            "10.0.0.10",
            "fd00::1",
            "[fd00::1]",
            "a-b.c1",
        ] {
            assert!(is_valid_host(ok), "{ok}");
        }
    }

    #[test]
    fn stage_must_be_absolute_without_parent_segments() {
        let cfg = |stage: &str| {
            SmbTargetConfig::parse(&format!(
                r#"{{"host":"h","share":"s","user":"u","stage":"{stage}"}}"#
            ))
            .unwrap()
        };
        assert!(cfg("relative/dir").stage_dir("x", Path::new("/s")).is_err());
        assert!(cfg("/a/../b").stage_dir("x", Path::new("/s")).is_err());
        assert!(cfg("/a/b").stage_dir("x", Path::new("/s")).is_ok());
    }

    #[test]
    fn prepare_stage_marks_new_dirs_and_refuses_foreign_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("orca");
        let stage = tmp.path().join("stage");
        prepare_stage(&stage, &state, &[]).unwrap();
        assert!(stage.join(STAGE_MARKER).is_file());
        // Idempotent once marked, even with content.
        fs::write(stage.join("x"), "y").unwrap();
        prepare_stage(&stage, &state, &[]).unwrap();

        let foreign = tmp.path().join("home");
        fs::create_dir_all(&foreign).unwrap();
        fs::write(foreign.join("photo.jpg"), "x").unwrap();
        assert!(prepare_stage(&foreign, &state, &[]).is_err());
        assert!(!foreign.join(STAGE_MARKER).exists());

        let empty = tmp.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        prepare_stage(&empty, &state, &[]).unwrap();
    }

    #[test]
    fn prepare_stage_rejects_overlap_with_local_store_and_other_stages() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("orca");
        assert!(prepare_stage(&state.join("backups/stage"), &state, &[]).is_err());
        assert!(prepare_stage(&state, &state, &[]).is_err());
        let other = [tmp.path().join("stages/a")];
        assert!(prepare_stage(&other[0].join("b"), &state, &other).is_err());
        assert!(prepare_stage(&tmp.path().join("stages"), &state, &other).is_err());
        assert!(prepare_stage(&tmp.path().join("stages/ab"), &state, &other).is_ok());
    }

    #[test]
    fn default_stage_is_outside_the_local_target_store() {
        let cfg = SmbTargetConfig::parse(r#"{"host":"h","share":"s","user":"u"}"#).unwrap();
        let state = Path::new("/home/u/.orca");
        let stage = cfg.stage_dir("a/b", state).unwrap();
        assert!(!stage.starts_with(state.join("backups")));
        assert_eq!(stage.file_name().unwrap(), "smb-a_b");
    }

    #[test]
    fn backing_key_and_remote_root_name_the_shared_folder() {
        let cfg = SmbTargetConfig::parse(
            r#"{"host":"10.0.0.10","share":"backups","path":"/game-saves/","user":"u"}"#,
        )
        .unwrap();
        assert_eq!(cfg.backing_key(), "smb://10.0.0.10/backups/game-saves");
        assert_eq!(cfg.remote_root(), ":smb:backups/game-saves");
        let root = SmbTargetConfig::parse(r#"{"host":"h","share":"s","user":"u"}"#).unwrap();
        assert_eq!(root.backing_key(), "smb://h/s");
    }

    #[test]
    fn row_name_is_namespaced_by_kind() {
        assert_eq!(row_name("saves"), "target:smb:saves");
    }

    fn row(id: &str, noun: &str, replica: i64, updated: &str, json: &str) -> DbRow {
        [
            ("id", DbValue::Text(id.into())),
            ("noun", DbValue::Text(noun.into())),
            ("is_replica", DbValue::Int(replica)),
            ("updated_at", DbValue::Text(updated.into())),
            ("json", DbValue::Text(json.into())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    #[test]
    fn pick_config_prefers_owned_then_newest_backup_row() {
        let rows = vec![
            row("1", "backup", 1, "2026-10-04T00:00:00Z", "replica-newer"),
            row("2", "backup", 0, "2026-10-01T00:00:00Z", "owned-older"),
            row("3", "backup", 0, "2026-10-02T00:00:00Z", "owned-newer"),
            row("4", "other", 0, "2026-10-09T00:00:00Z", "wrong-noun"),
        ];
        assert_eq!(pick_config_json(&rows).as_deref(), Some("owned-newer"));
        assert_eq!(
            pick_config_json(&rows[..1]).as_deref(),
            Some("replica-newer")
        );
        assert_eq!(pick_config_json(&rows[3..]), None);
    }

    // ── dispatch ──

    #[test]
    fn backend_def_and_dispatcher_route_only_their_prefix() {
        let def = backend_def();
        assert_eq!(def.domain, "backup_target");
        assert_eq!(def.name, TARGET_KIND);
        assert_eq!(def.invoke_prefix, INVOKE_PREFIX);
        assert!(dispatcher("storage.__backend.smb.mount", Value::Null).is_none());
        let title = dispatcher("smb.__backup_target.title", Value::Null).unwrap();
        assert_eq!(title.unwrap(), Value::String("SMB share".into()));
        let fits = dispatcher(
            "smb.__backup_target.fits",
            serde_json::json!({"placement":{"labels":[]}}),
        )
        .unwrap();
        assert_eq!(fits.unwrap(), Value::Bool(true));
    }

    // ── plan ──

    #[test]
    fn plan_classifies_each_slot_by_where_it_moved() {
        let baseline = set(&["kept", "pruned-here", "pruned-there", "gone-both"]);
        let local = set(&["kept", "pruned-there", "new", "collide"]);
        let remote = set(&["kept", "pruned-here", "theirs", "collide"]);
        let p = plan(&local, &baseline, &remote).unwrap();
        assert_eq!(p.remote_delete, set(&["pruned-here"]));
        assert_eq!(p.local_delete, set(&["pruned-there"]));
        assert_eq!(p.push, set(&["new"]));
        assert_eq!(p.check, set(&["collide"]));
    }

    #[test]
    fn plan_never_deletes_outside_the_baseline() {
        let p = plan(&set(&["a"]), &set(&[]), &set(&["b"])).unwrap();
        assert!(p.remote_delete.is_empty() && p.local_delete.is_empty());
        assert_eq!(p.push, set(&["a"]));
    }

    #[test]
    fn plan_refuses_to_mirror_an_emptied_side() {
        assert!(plan(&set(&["a"]), &set(&["a"]), &set(&[])).is_err());
        assert!(plan(&set(&[]), &set(&["a"]), &set(&["a"])).is_err());
        assert!(plan(&set(&[]), &set(&[]), &set(&[])).is_ok());
    }

    #[test]
    fn plan_caps_deletions_per_pass() {
        let all: Vec<String> = (0..16).map(|i| format!("s{i:02}")).collect();
        let baseline: BTreeSet<String> = all.iter().cloned().collect();
        let keep = |n: usize| -> BTreeSet<String> { all[n..].iter().cloned().collect() };
        // Cap is max(3, 16/4) = 4.
        assert!(plan(&baseline, &baseline, &keep(4)).is_ok());
        assert!(plan(&baseline, &baseline, &keep(5)).is_err());
        assert!(plan(&keep(5), &baseline, &baseline).is_err());
        // Small baselines still allow up to 3.
        let small = set(&["a", "b", "c", "d"]);
        assert!(plan(&small, &small, &set(&["d"])).is_ok());
    }

    #[test]
    fn nested_slots_flags_both_ancestor_and_descendant() {
        let s = set(&["g/1", "g/1/x", "g/10", "g/2", "h/1/a/b", "h/1"]);
        assert_eq!(nested_slots(&s), set(&["g/1", "g/1/x", "h/1", "h/1/a/b"]));
    }

    // ── manifests ──

    fn manifest(slot: &str, created_ms: i64, body: &str, path: &str) -> String {
        let rec = BackupRecord {
            id: slot.rsplit('/').next().unwrap().to_string(),
            kind: "game-saves".into(),
            instance: "x".into(),
            created_ms,
            path: path.into(),
            size_bytes: body.len() as u64,
            file_count: 1,
            checksum: None,
            note: None,
            system: String::new(),
        };
        serde_json::to_string_pretty(&rec).unwrap()
    }

    #[test]
    fn rewrite_manifest_pins_path_to_this_hosts_copy() {
        let m = manifest("g/1", 1, "x", "/etc");
        let out = rewrite_manifest(&m, "g/1", Path::new("/stage/g/1/payload")).unwrap();
        let rec: BackupRecord = serde_json::from_str(&out).unwrap();
        assert_eq!(rec.path, "/stage/g/1/payload");
    }

    #[test]
    fn validate_manifest_rejects_bad_or_mismatched_ids() {
        let with_id = |id: &str| manifest("g/1", 1, "x", "/p").replace("\"1\"", &format!("{id:?}"));
        assert!(validate_manifest(&with_id("1"), "g/1").is_ok());
        assert!(validate_manifest(&with_id("2"), "g/1").is_err());
        assert!(validate_manifest(&with_id("../1"), "g/1").is_err());
        assert!(validate_manifest(&with_id("a/1"), "g/1").is_err());
        assert!(validate_manifest(&with_id(".."), "g/..").is_err());
        assert!(validate_manifest("{not json", "g/1").is_err());
    }

    // ── reconcile against a directory standing in for the share ──

    /// Mimics what rclone does against SMB: no hashes (only sizes), pulls never
    /// overwrite an existing file, manifests go last on push and first on
    /// removal.
    struct DirRemote {
        root: PathBuf,
        fail_pull: Cell<bool>,
        fail_push: Cell<bool>,
    }

    impl DirRemote {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
                fail_pull: Cell::new(false),
                fail_push: Cell::new(false),
            }
        }
    }

    fn copy_tree(src: &Path, dst: &Path, overwrite: bool) {
        fs::create_dir_all(dst).unwrap();
        for e in fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let to = dst.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_tree(&e.path(), &to, overwrite);
            } else if overwrite || !to.exists() {
                fs::copy(e.path(), to).unwrap();
            }
        }
    }

    fn walk_sizes(root: &Path) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                } else {
                    let rel = e
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    out.insert(rel, e.metadata().unwrap().len());
                }
            }
        }
        out
    }

    impl SlotRemote for DirRemote {
        fn list(&self) -> Result<BTreeSet<String>, String> {
            Ok(local_slots(&self.root)?.committed)
        }
        fn push(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
            if self.fail_push.get() {
                return Err("push failed".into());
            }
            for s in slots {
                copy_tree(
                    &stage.join(s).join(PAYLOAD),
                    &self.root.join(s).join(PAYLOAD),
                    true,
                );
            }
            for s in slots {
                fs::copy(
                    stage.join(s).join(MANIFEST),
                    self.root.join(s).join(MANIFEST),
                )
                .unwrap();
            }
            Ok(())
        }
        fn pull_payloads(&self, dest: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
            if self.fail_pull.get() {
                return Err("pull failed".into());
            }
            for s in slots {
                let src = self.root.join(s).join(PAYLOAD);
                if src.is_dir() {
                    copy_tree(&src, &dest.join(s).join(PAYLOAD), false);
                }
            }
            Ok(())
        }
        fn manifest(&self, slot: &str) -> Result<String, String> {
            fs::read_to_string(self.root.join(slot).join(MANIFEST)).map_err(|e| e.to_string())
        }
        fn sizes(&self, slot: &str) -> Result<BTreeMap<String, u64>, String> {
            Ok(walk_sizes(&self.root.join(slot)))
        }
        fn remove(&self, slot: &str) -> Result<(), String> {
            fs::remove_file(self.root.join(slot).join(MANIFEST)).map_err(|e| e.to_string())?;
            fs::remove_dir_all(self.root.join(slot)).map_err(|e| e.to_string())
        }
    }

    fn write_slot_at(root: &Path, slot: &str, body: &str, created_ms: i64) {
        let dir = root.join(slot);
        fs::create_dir_all(dir.join(PAYLOAD)).unwrap();
        fs::write(dir.join(PAYLOAD).join("save.dat"), body).unwrap();
        let path = dir.join(PAYLOAD).to_string_lossy().into_owned();
        fs::write(dir.join(MANIFEST), manifest(slot, created_ms, body, &path)).unwrap();
    }

    fn write_slot(root: &Path, slot: &str, body: &str) {
        write_slot_at(root, slot, body, 1)
    }

    fn committed(stage: &Path) -> BTreeSet<String> {
        local_slots(stage).unwrap().committed
    }

    fn body(root: &Path, slot: &str) -> String {
        fs::read_to_string(root.join(slot).join("payload/save.dat")).unwrap()
    }

    fn binding() -> Binding {
        Binding {
            backing_key: "smb://h/s/p".into(),
            target: "saves".into(),
        }
    }

    struct Fleet {
        _tmp: tempfile::TempDir,
        remote: DirRemote,
        a: PathBuf,
        b: PathBuf,
    }

    fn fleet() -> Fleet {
        let tmp = tempfile::tempdir().unwrap();
        let (r, a, b) = (
            tmp.path().join("remote"),
            tmp.path().join("a"),
            tmp.path().join("b"),
        );
        for d in [&r, &a, &b] {
            fs::create_dir_all(d).unwrap();
        }
        Fleet {
            remote: DirRemote::new(&r),
            _tmp: tmp,
            a,
            b,
        }
    }

    impl Fleet {
        fn sync(&self, stage: &Path) -> Result<Outcome, String> {
            reconcile(stage, &binding(), &self.remote)
        }
    }

    #[test]
    fn local_slots_splits_committed_from_in_progress_and_skips_own_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        write_slot(tmp.path(), "g/x/1", "a");
        fs::create_dir_all(tmp.path().join("g/x/2").join(PAYLOAD)).unwrap();
        fs::write(tmp.path().join("g/x/1/payload/manifest.json"), "{}").unwrap();
        write_slot(&tmp.path().join(INCOMING), "g/x/3", "a");
        write_slot(&tmp.path().join(".orca-anything"), "g/x/4", "a");
        fs::write(tmp.path().join(BASELINE), "[]").unwrap();
        let s = local_slots(tmp.path()).unwrap();
        assert_eq!(s.committed, set(&["g/x/1"]));
        assert_eq!(s.in_progress, set(&["g/x/2"]));
    }

    #[test]
    fn stale_stage_sync_never_deletes_another_hosts_new_slot() {
        let f = fleet();
        write_slot(&f.a, "g/a/1", "a1");
        f.sync(&f.a).unwrap();
        f.sync(&f.b).unwrap();
        assert_eq!(committed(&f.b), set(&["g/a/1"]));

        // A adds a slot B has not seen; B then backs up from its stale stage
        // and syncs without any refresh first (the backup.run path).
        write_slot(&f.a, "g/a/2", "a2");
        f.sync(&f.a).unwrap();
        write_slot(&f.b, "g/b/1", "b1");
        f.sync(&f.b).unwrap();

        assert_eq!(committed(&f.remote.root), set(&["g/a/1", "g/a/2", "g/b/1"]));
        assert_eq!(committed(&f.b), set(&["g/a/1", "g/a/2", "g/b/1"]));
    }

    #[test]
    fn prunes_propagate_both_ways() {
        let f = fleet();
        for s in ["g/1", "g/2", "g/3"] {
            write_slot(&f.a, s, s);
        }
        f.sync(&f.a).unwrap();
        f.sync(&f.b).unwrap();

        fs::remove_dir_all(f.b.join("g/1")).unwrap();
        f.sync(&f.b).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/2", "g/3"]));

        f.sync(&f.a).unwrap();
        assert_eq!(committed(&f.a), set(&["g/2", "g/3"]));
    }

    #[test]
    fn failed_push_keeps_the_slot_and_retries() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        f.remote.fail_push.set(true);
        assert!(f.sync(&f.a).is_err());
        assert_eq!(committed(&f.a), set(&["g/1"]));
        f.remote.fail_push.set(false);
        f.sync(&f.a).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/1"]));
    }

    #[test]
    fn failed_pull_never_turns_unpulled_slots_into_remote_deletes() {
        let f = fleet();
        write_slot(&f.a, "g/a/1", "a1");
        f.sync(&f.a).unwrap();

        write_slot(&f.b, "g/b/1", "b1");
        f.remote.fail_pull.set(true);
        assert!(f.sync(&f.b).is_err());
        assert!(!read_baseline(&f.b, &binding()).contains("g/a/1"));
        assert!(
            !f.b.join("g/a/1").exists(),
            "nothing half-pulled is visible"
        );

        f.remote.fail_pull.set(false);
        f.sync(&f.b).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/a/1", "g/b/1"]));
        assert_eq!(committed(&f.b), set(&["g/a/1", "g/b/1"]));
    }

    // H1
    #[test]
    fn pulled_manifest_path_is_rewritten_to_the_local_payload() {
        let f = fleet();
        write_slot(&f.remote.root, "g/1", "x");
        let m = f.remote.root.join("g/1").join(MANIFEST);
        fs::write(&m, manifest("g/1", 1, "x", "/etc")).unwrap();
        f.sync(&f.b).unwrap();
        let rec: BackupRecord =
            serde_json::from_str(&fs::read_to_string(f.b.join("g/1").join(MANIFEST)).unwrap())
                .unwrap();
        assert_eq!(rec.path, f.b.join("g/1/payload").to_string_lossy());
    }

    // H1
    #[test]
    fn remote_slot_with_a_bad_manifest_is_not_pulled() {
        let f = fleet();
        write_slot(&f.remote.root, "g/1", "x");
        let m = f.remote.root.join("g/1").join(MANIFEST);
        fs::write(
            &m,
            manifest("g/1", 1, "x", "/p").replace("\"1\"", "\"../../x\""),
        )
        .unwrap();
        write_slot(&f.remote.root, "g/2", "y");
        let err = f.sync(&f.b).unwrap_err();
        assert!(err.contains("g/1"), "{err}");
        assert!(!f.b.join("g/1").exists());
        assert_eq!(committed(&f.b), set(&["g/2"]));
        assert!(!read_baseline(&f.b, &binding()).contains("g/1"));
    }

    // H2
    #[test]
    fn remote_tampering_never_rewrites_a_local_backup() {
        let f = fleet();
        write_slot(&f.a, "g/1", "original");
        f.sync(&f.a).unwrap();
        f.sync(&f.b).unwrap();
        fs::write(f.remote.root.join("g/1/payload/save.dat"), "tampered").unwrap();
        fs::write(f.remote.root.join("g/1/payload/extra"), "planted").unwrap();
        f.sync(&f.a).unwrap();
        f.sync(&f.b).unwrap();
        for host in [&f.a, &f.b] {
            assert_eq!(body(host, "g/1"), "original");
            assert!(!host.join("g/1/payload/extra").exists());
        }
    }

    // H3
    #[test]
    fn same_id_from_two_hosts_is_a_conflict_whatever_the_sizes() {
        for (a_body, b_body) in [("from-a", "from-bbbb"), ("from-a", "from-b")] {
            let f = fleet();
            write_slot_at(&f.a, "g/1", a_body, 100);
            f.sync(&f.a).unwrap();
            write_slot_at(&f.b, "g/1", b_body, 200);
            let err = f.sync(&f.b).unwrap_err();
            assert!(err.contains("g/1"), "{err}");
            assert_eq!(body(&f.remote.root, "g/1"), a_body);
            assert_eq!(body(&f.b, "g/1"), b_body);
            // Still flagged on the next pass rather than silently adopted.
            assert!(f.sync(&f.b).is_err());
            assert_eq!(body(&f.b, "g/1"), b_body);
        }
    }

    // H3
    #[test]
    fn identical_slot_is_adopted_when_the_baseline_was_lost() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        f.sync(&f.a).unwrap();
        f.sync(&f.b).unwrap();
        for host in [&f.a, &f.b] {
            fs::remove_file(host.join(BASELINE)).unwrap();
            f.sync(host).unwrap();
            assert_eq!(read_baseline(host, &binding()), set(&["g/1"]));
        }
    }

    // M4
    #[test]
    fn nested_slots_are_never_acted_on() {
        let f = fleet();
        write_slot(&f.a, "g/1", "outer");
        write_slot(&f.remote.root, "g/1/inner", "inner");
        let err = f.sync(&f.a).unwrap_err();
        assert!(err.contains("nested"), "{err}");
        assert!(!f.remote.root.join("g/1").join(MANIFEST).exists());
        assert!(!f.a.join("g/1/inner").exists());
        assert_eq!(body(&f.a, "g/1"), "outer");
    }

    // M4 / L17
    #[test]
    fn local_delete_removes_only_the_slots_manifest_and_payload() {
        let f = fleet();
        for s in ["g/1", "g/2", "g/3"] {
            write_slot(&f.a, s, s);
        }
        f.sync(&f.a).unwrap();
        fs::write(f.a.join("g/1/notes.txt"), "keep").unwrap();
        f.remote.remove("g/1").unwrap();
        f.sync(&f.a).unwrap();
        assert!(!f.a.join("g/1").join(MANIFEST).exists());
        assert!(!f.a.join("g/1").join(PAYLOAD).exists());
        assert_eq!(
            fs::read_to_string(f.a.join("g/1/notes.txt")).unwrap(),
            "keep"
        );
        assert!(!f.a.join(TRASH).read_dir().unwrap().any(|_| true));
    }

    // M4
    #[test]
    fn mass_remote_deletion_is_refused_and_the_stage_survives() {
        let f = fleet();
        let slots: Vec<String> = (0..8).map(|i| format!("g/{i}")).collect();
        for s in &slots {
            write_slot(&f.a, s, s);
        }
        f.sync(&f.a).unwrap();
        for s in &slots[..4] {
            f.remote.remove(s).unwrap();
        }
        let err = f.sync(&f.a).unwrap_err();
        assert!(err.contains("cap"), "{err}");
        assert_eq!(committed(&f.a).len(), 8);
    }

    #[test]
    fn an_emptied_remote_is_refused_and_the_stage_survives() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        f.sync(&f.a).unwrap();
        fs::remove_dir_all(f.remote.root.join("g")).unwrap();
        assert!(f.sync(&f.a).is_err());
        assert_eq!(committed(&f.a), set(&["g/1"]));
    }

    // M5
    #[test]
    fn a_baseline_for_another_remote_is_ignored() {
        let f = fleet();
        for s in ["g/1", "g/2"] {
            write_slot(&f.a, s, s);
        }
        f.sync(&f.a).unwrap();
        fs::remove_dir_all(f.a.join("g/1")).unwrap();
        let moved = Binding {
            backing_key: "smb://other/share".into(),
            target: "saves".into(),
        };
        reconcile(&f.a, &moved, &f.remote).unwrap();
        // Treated as first contact: nothing purged, the slot comes back.
        assert_eq!(committed(&f.remote.root), set(&["g/1", "g/2"]));
        assert_eq!(committed(&f.a), set(&["g/1", "g/2"]));
    }

    // L14
    #[test]
    fn an_unparsable_baseline_reads_as_empty() {
        let f = fleet();
        for s in ["g/1", "g/2"] {
            write_slot(&f.a, s, s);
        }
        f.sync(&f.a).unwrap();
        fs::remove_dir_all(f.a.join("g/1")).unwrap();
        fs::write(f.a.join(BASELINE), "{garbage").unwrap();
        f.sync(&f.a).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/1", "g/2"]));
    }

    // M8
    #[test]
    fn invalid_local_manifest_is_reported_and_never_pushed() {
        let f = fleet();
        write_slot(&f.a, "g/1", "bad");
        fs::write(f.a.join("g/1").join(MANIFEST), "{}").unwrap();
        write_slot(&f.a, "g/2", "good");
        let err = f.sync(&f.a).unwrap_err();
        assert!(err.contains("g/1"), "{err}");
        assert_eq!(committed(&f.remote.root), set(&["g/2"]));
    }

    // M8
    #[test]
    fn the_stage_lock_is_exclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let held = StageLock::acquire(tmp.path(), Duration::from_secs(1)).unwrap();
        assert!(StageLock::acquire(tmp.path(), Duration::from_millis(100)).is_err());
        drop(held);
        assert!(StageLock::acquire(tmp.path(), Duration::from_millis(100)).is_ok());
    }

    #[test]
    fn in_progress_slot_is_never_pulled_into() {
        let f = fleet();
        write_slot(&f.a, "g/1", "theirs");
        f.sync(&f.a).unwrap();
        fs::create_dir_all(f.b.join("g/1").join(PAYLOAD)).unwrap();
        fs::write(f.b.join("g/1/payload/mine.dat"), "mine").unwrap();
        f.sync(&f.b).unwrap();
        assert!(!f.b.join("g/1/payload/save.dat").exists());
        assert!(!f.b.join("g/1").join(MANIFEST).exists());
    }

    /// The real rclone command lines (filters over stdin, two-pass push,
    /// ignore-existing pull, lsf listing, cat, removal) against a plain
    /// directory standing in for the share. Needs `rclone` on PATH or
    /// `ORCA_RCLONE_BIN`.
    #[test]
    #[ignore = "needs an rclone binary"]
    fn rclone_reconcile_against_a_local_dir() {
        let bin = std::env::var("ORCA_RCLONE_BIN")
            .ok()
            .or_else(|| plugin_toolkit::path::which("rclone"))
            .expect("rclone on PATH or ORCA_RCLONE_BIN");
        let f = fleet();
        let r = RcloneRemote {
            rclone: Rclone::connect(PathBuf::from(&bin), "h", "u", "pw").unwrap(),
            root: f.remote.root.to_string_lossy().into_owned(),
        };
        let sync = |stage: &Path| reconcile(stage, &binding(), &r);
        for s in ["g/[EU] a/1", "g/[EU] a/2", "g/[EU] a/3"] {
            write_slot(&f.a, s, s);
        }
        sync(&f.a).unwrap();
        sync(&f.b).unwrap();
        assert_eq!(
            committed(&f.b),
            set(&["g/[EU] a/1", "g/[EU] a/2", "g/[EU] a/3"])
        );
        let rec: BackupRecord = serde_json::from_str(
            &fs::read_to_string(f.b.join("g/[EU] a/1").join(MANIFEST)).unwrap(),
        )
        .unwrap();
        assert_eq!(rec.path, f.b.join("g/[EU] a/1/payload").to_string_lossy());

        fs::remove_dir_all(f.b.join("g/[EU] a/1")).unwrap();
        write_slot(&f.b, "g/b/1", "b1");
        sync(&f.b).unwrap();
        sync(&f.a).unwrap();
        let want = set(&["g/[EU] a/2", "g/[EU] a/3", "g/b/1"]);
        assert_eq!(committed(&f.remote.root), want);
        assert_eq!(committed(&f.a), want);

        fs::write(f.remote.root.join("g/b/1/payload/save.dat"), "XX").unwrap();
        sync(&f.a).unwrap();
        assert_eq!(body(&f.a, "g/b/1"), "b1");

        write_slot_at(&f.a, "g/c/1", "from-a", 1);
        write_slot_at(&f.b, "g/c/1", "from-b", 2);
        sync(&f.a).unwrap();
        assert!(sync(&f.b).is_err());
        fs::remove_file(f.b.join(BASELINE)).unwrap();
        assert!(sync(&f.b).unwrap_err().contains("g/c/1"));
        assert!(r.remove("g/missing").is_ok());
    }

    /// End-to-end against a real share. Run with:
    /// `ORCA_SMB_LIVE_HOST=… ORCA_SMB_LIVE_SHARE=… ORCA_SMB_LIVE_PATH=… \
    ///  ORCA_SMB_LIVE_USER=… ORCA_SMB_LIVE_PASS=… cargo test -- --ignored live_`
    #[test]
    #[ignore = "needs rclone and a writable SMB share"]
    fn live_reconcile_round_trips_through_a_real_share() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let bin = PathBuf::from(plugin_toolkit::path::which("rclone").expect("rclone on PATH"));
        let rc = Rclone::connect(
            bin,
            &var("ORCA_SMB_LIVE_HOST"),
            &var("ORCA_SMB_LIVE_USER"),
            &var("ORCA_SMB_LIVE_PASS"),
        )
        .unwrap();
        let remote = RcloneRemote {
            rclone: rc,
            root: rclone::remote_root(&var("ORCA_SMB_LIVE_SHARE"), &var("ORCA_SMB_LIVE_PATH")),
        };
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write_slot(a.path(), "live/1", "one");
        reconcile(a.path(), &binding(), &remote).unwrap();
        reconcile(b.path(), &binding(), &remote).unwrap();
        assert!(committed(b.path()).contains("live/1"));
        write_slot(a.path(), "live/2", "two");
        fs::remove_dir_all(a.path().join("live/1")).unwrap();
        reconcile(a.path(), &binding(), &remote).unwrap();
        assert!(!remote.list().unwrap().contains("live/1"));
        remote.remove("live/2").unwrap();
    }
}
