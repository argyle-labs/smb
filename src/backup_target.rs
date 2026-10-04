//! `smb` backup TARGET: the generic backup store writes into a local stage dir,
//! and the stage is reconciled with an SMB share over rclone.
//!
//! A target instance `<name>` is configured by the `backup`/`target:smb:<name>`
//! config row (as core's `local` target reads `target:local:<name>`):
//!
//! ```json
//! {"host":"10.0.0.10","share":"backups","path":"game-saves","user":"skey",
//!  "passwordSecret":"smb.<name>.password","stage":"/optional/local/dir"}
//! ```
//!
//! ## Reconcile, and why `sync` is safe on its own
//!
//! Several hosts may share one remote (game saves are meant to), and the host
//! calls `refresh` only before list/restore — a `backup.run` goes open → write
//! → prune → `sync` with no refresh. A blind `rclone sync stage -> remote` from
//! a stale stage would delete every slot another host added since. So both
//! `sync` and `refresh` run the same slot-level three-way [`reconcile`]: the
//! stage keeps a baseline of the slots last confirmed on BOTH sides, and
//! * a slot in the baseline but gone from the stage was pruned here → purge it
//!   remotely;
//! * a slot in the baseline but gone from the remote was pruned elsewhere →
//!   drop it from the stage;
//! * a stage slot not in the baseline is new here → push it (a same-path slot
//!   already on the remote is adopted only if identical, else reported);
//! * every remote slot is then pulled (a delta copy).
//!
//! Nothing outside the baseline is ever deleted, so a stale stage can only
//! delay retention, never destroy another host's backups. `bisync` was not
//! used: it reconciles files, not slots, so it would push a half-written slot,
//! cannot tell a same-id collision from an update, and needs a `--resync`
//! bootstrap plus its own lock/state recovery.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use plugin_toolkit::abi::{BackendDef, DbOp, DbRow, DbValue};
use plugin_toolkit::backend_def::backup_target_backend_def;
use plugin_toolkit::backup::{dispatch_target_op, BackupTargetPlugin};
use plugin_toolkit::path::expand_tilde;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use crate::rclone::{self, Rclone};

/// The backup target kind this plugin contributes.
pub const TARGET_KIND: &str = "smb";
/// Bridge invoke-prefix for the `smb` backup TARGET.
const INVOKE_PREFIX: &str = "smb.__backup_target";
/// Stage-root file recording the slots last confirmed on both sides. Lives in
/// the stage itself so a wiped stage also forgets it and starts fresh.
const BASELINE: &str = ".orca-smb-baseline.json";
const MANIFEST: &str = "manifest.json";
const PAYLOAD: &str = "payload";

static RECONCILE: Mutex<()> = Mutex::new(());

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
    /// Secret holding the password. Defaults to `smb.<name>.password`, the
    /// plugin's own secret namespace.
    #[orca(default)]
    pub password_secret: Option<String>,
    /// Local stage dir. Defaults to `<orca state dir>/backup-stage/smb-<name>`.
    #[orca(default)]
    pub stage: Option<String>,
}

impl SmbTargetConfig {
    pub fn parse(json: &str) -> Result<Self, String> {
        let cfg: Self =
            serde_json::from_str(json).map_err(|e| format!("invalid smb target config: {e}"))?;
        for (field, v) in [
            ("host", &cfg.host),
            ("share", &cfg.share),
            ("user", &cfg.user),
        ] {
            if v.trim().is_empty() {
                return Err(format!("smb target config: `{field}` is required"));
            }
        }
        if cfg.share.trim_matches('/').contains('/') {
            return Err("smb target config: `share` is a share name, not a path".into());
        }
        let path = cfg.path.trim_matches('/');
        if !path.is_empty() && path.split('/').any(|s| matches!(s, "" | "." | "..")) {
            return Err(format!("smb target config: bad `path` {:?}", cfg.path));
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
        let share = self.share.trim_matches('/');
        let path = self.path.trim_matches('/');
        if path.is_empty() {
            format!("smb://{}/{share}", self.host.trim())
        } else {
            format!("smb://{}/{share}/{path}", self.host.trim())
        }
    }

    pub fn remote_root(&self) -> String {
        rclone::remote_root(&self.share, &self.path)
    }

    pub fn stage_dir(&self, name: &str, state_dir: &Path) -> PathBuf {
        match self
            .stage
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => PathBuf::from(expand_tilde(s)),
            // Outside `<state>/backups`: that is the `local` target's store
            // root, which would list and prune these slots as its own.
            None => state_dir
                .join("backup-stage")
                .join(format!("smb-{}", name.replace(['/', '\\'], "_"))),
        }
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

/// Pick the `backup` row out of every `config_rows` row with this name, with
/// core's precedence: an owned row over a replica, then newest, then lowest id.
pub fn pick_config_json(rows: &[DbRow]) -> Option<String> {
    let is_replica = |r: &DbRow| match r.get("is_replica") {
        Some(DbValue::Int(n)) => *n != 0,
        Some(DbValue::Bool(b)) => *b,
        _ => false,
    };
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

fn load_config(name: &str) -> Result<SmbTargetConfig, String> {
    let row = row_name(name);
    let reply = plugin_toolkit::runtime::db_op(&DbOp::Get {
        namespace: String::new(),
        table: "config_rows".into(),
        key_col: "name".into(),
        key: row.clone(),
    })
    .map_err(|e| format!("read backup/{row} config: {e:#}"))?;
    let json = pick_config_json(&reply.rows)
        .ok_or_else(|| format!("no backup/{row} config row for smb target `{name}`"))?;
    SmbTargetConfig::parse(&json)
}

fn state_dir() -> Result<PathBuf, String> {
    plugin_toolkit::contract::config::state_dir().map_err(|e| format!("{e:#}"))
}

// ── Reconcile ─────────────────────────────────────────────────────────────

/// What the stage holds: complete slots, and slots still being written.
#[derive(Debug, Default)]
pub(crate) struct LocalSlots {
    pub committed: BTreeSet<String>,
    pub in_progress: BTreeSet<String>,
}

/// Walk the stage like the generic store does: a dir with `manifest.json` is a
/// committed slot, one with only `payload/` is in progress, and no walk enters
/// a payload.
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
            if ft.is_dir() {
                if entry.file_name() == PAYLOAD {
                    payload = true;
                } else {
                    stack.push(entry.path());
                }
            } else if entry.file_name() == MANIFEST {
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

fn read_baseline(stage: &Path) -> Result<BTreeSet<String>, String> {
    let path = stage.join(BASELINE);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("parse {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn write_baseline(stage: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
    let path = stage.join(BASELINE);
    let tmp = stage.join(format!("{BASELINE}.tmp"));
    let json = serde_json::to_string(slots).map_err(|e| e.to_string())?;
    fs::write(&tmp, json).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("write {}: {e}", path.display()))
}

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
    Ok(Plan {
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
    })
}

/// The remote operations a reconcile needs, so the safety logic is testable
/// without an SMB server.
pub(crate) trait SlotRemote {
    fn list(&self) -> Result<BTreeSet<String>, String>;
    fn push(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String>;
    fn pull(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String>;
    fn purge(&self, slot: &str) -> Result<(), String>;
    fn identical(&self, stage: &Path, slot: &str) -> bool;
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
            .copy_slots(&stage.to_string_lossy(), &self.root, slots)
    }
    fn pull(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
        self.rclone
            .copy_slots(&self.root, &stage.to_string_lossy(), slots)
    }
    fn purge(&self, slot: &str) -> Result<(), String> {
        self.rclone.purge(&self.at(slot))
    }
    fn identical(&self, stage: &Path, slot: &str) -> bool {
        self.rclone
            .identical(&stage.join(slot).to_string_lossy(), &self.at(slot))
    }
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
pub(crate) fn reconcile(stage: &Path, remote: &dyn SlotRemote) -> Result<Outcome, String> {
    let _guard = RECONCILE.lock().unwrap_or_else(|e| e.into_inner());
    let local = local_slots(stage)?;
    let baseline = read_baseline(stage)?;
    let p = plan(&local.committed, &baseline, &remote.list()?)?;

    for slot in &p.remote_delete {
        remote.purge(slot)?;
    }
    let conflicts: BTreeSet<String> = p
        .check
        .iter()
        .filter(|s| !remote.identical(stage, s))
        .cloned()
        .collect();
    if !p.push.is_empty() {
        remote.push(stage, &p.push)?;
    }
    for slot in &p.local_delete {
        let dir = stage.join(slot);
        fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {e}", dir.display()))?;
    }

    let remote_now = remote.list()?;
    let pull: BTreeSet<String> = remote_now
        .iter()
        .filter(|s| !conflicts.contains(*s) && !local.in_progress.contains(*s))
        .cloned()
        .collect();
    let pulled = if pull.is_empty() {
        Ok(())
    } else {
        remote.pull(stage, &pull)
    };
    // Only slots present on both sides enter the baseline: one listed remotely
    // but not (yet) pulled must never later read as "pruned here".
    let local_now = local_slots(stage)?.committed;
    let synced: BTreeSet<String> = remote_now
        .intersection(&local_now)
        .filter(|s| !conflicts.contains(*s))
        .cloned()
        .collect();
    write_baseline(stage, &synced)?;
    pulled?;

    if !conflicts.is_empty() {
        return Err(format!(
            "slot(s) already exist on the remote with different contents (same backup id \
             written by another host); kept local copies, not overwritten: {}",
            conflicts.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(Outcome {
        pushed: p.push.len(),
        purged: p.remote_delete.len(),
        dropped: p.local_delete.len(),
        pulled: pull.difference(&local.committed).count(),
    })
}

// ── Target ────────────────────────────────────────────────────────────────

/// The `smb` backup target.
#[derive(Debug, Default)]
pub struct SmbBackupTarget;

impl SmbBackupTarget {
    fn reconcile_named(&self, name: &str) -> Result<(), String> {
        let cfg = load_config(name)?;
        let stage = cfg.stage_dir(name, &state_dir()?);
        fs::create_dir_all(&stage).map_err(|e| format!("create {}: {e}", stage.display()))?;
        let password = plugin_toolkit::secrets::get_required(&cfg.password_ref(name))
            .map_err(|e| format!("smb target `{name}`: {e:#}"))?;
        let remote = RcloneRemote {
            rclone: Rclone::connect(rclone::resolve()?, &cfg.host, &cfg.user, &password)?,
            root: cfg.remote_root(),
        };
        let out = reconcile(&stage, &remote).map_err(|e| format!("smb target `{name}`: {e}"))?;
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
        let cfg = load_config(name)?;
        rclone::resolve()?;
        let stage = cfg.stage_dir(name, &state_dir()?);
        fs::create_dir_all(&stage).map_err(|e| format!("create {}: {e}", stage.display()))?;
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
            r#"{"host":"10.0.0.10","share":"backups","path":"game-saves","user":"skey",
                "passwordSecret":"smb.saves.password","stage":"/var/stage"}"#,
        )
        .unwrap();
        assert_eq!(cfg.host, "10.0.0.10");
        assert_eq!(cfg.password_secret.as_deref(), Some("smb.saves.password"));
        assert_eq!(cfg.stage.as_deref(), Some("/var/stage"));

        let min = SmbTargetConfig::parse(r#"{"host":"h","share":"backups","user":"u"}"#).unwrap();
        assert_eq!(min.path, "");
        assert_eq!(min.password_ref("saves"), "smb.saves.password");
        assert_eq!(
            min.stage_dir("saves", Path::new("/home/u/.orca")),
            PathBuf::from("/home/u/.orca/backup-stage/smb-saves")
        );
    }

    #[test]
    fn config_rejects_missing_or_unsafe_fields() {
        for bad in [
            r#"{"share":"s","user":"u"}"#,
            r#"{"host":" ","share":"s","user":"u"}"#,
            r#"{"host":"h","share":"","user":"u"}"#,
            r#"{"host":"h","share":"s"}"#,
            r#"{"host":"h","share":"a/b","user":"u"}"#,
            r#"{"host":"h","share":"s","user":"u","path":"a/../b"}"#,
            r#"{"host":"h","share":"s","user":"u","path":"a//b"}"#,
        ] {
            assert!(SmbTargetConfig::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn default_stage_is_outside_the_local_target_store() {
        let cfg = SmbTargetConfig::parse(r#"{"host":"h","share":"s","user":"u"}"#).unwrap();
        let state = Path::new("/home/u/.orca");
        let stage = cfg.stage_dir("a/b", state);
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
        // No baseline (first contact): nothing is deleted on either side.
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

    // ── reconcile against a directory standing in for the share ──

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

    fn copy_tree(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for e in fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let to = dst.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_tree(&e.path(), &to);
            } else {
                fs::copy(e.path(), to).unwrap();
            }
        }
    }

    fn tree_eq(a: &Path, b: &Path) -> bool {
        let read = |p: &Path| -> Vec<(String, Vec<u8>)> {
            let mut out = Vec::new();
            let mut stack = vec![p.to_path_buf()];
            while let Some(d) = stack.pop() {
                for e in fs::read_dir(&d).unwrap() {
                    let e = e.unwrap();
                    if e.file_type().unwrap().is_dir() {
                        stack.push(e.path());
                    } else {
                        let rel = e.path().strip_prefix(p).unwrap().display().to_string();
                        out.push((rel, fs::read(e.path()).unwrap()));
                    }
                }
            }
            out.sort();
            out
        };
        a.is_dir() && b.is_dir() && read(a) == read(b)
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
                copy_tree(&stage.join(s), &self.root.join(s));
            }
            Ok(())
        }
        fn pull(&self, stage: &Path, slots: &BTreeSet<String>) -> Result<(), String> {
            if self.fail_pull.get() {
                return Err("pull failed".into());
            }
            for s in slots {
                copy_tree(&self.root.join(s), &stage.join(s));
            }
            Ok(())
        }
        fn purge(&self, slot: &str) -> Result<(), String> {
            fs::remove_dir_all(self.root.join(slot)).map_err(|e| e.to_string())
        }
        fn identical(&self, stage: &Path, slot: &str) -> bool {
            tree_eq(&stage.join(slot), &self.root.join(slot))
        }
    }

    fn write_slot(stage: &Path, slot: &str, body: &str) {
        let dir = stage.join(slot);
        fs::create_dir_all(dir.join(PAYLOAD)).unwrap();
        fs::write(dir.join(PAYLOAD).join("save.dat"), body).unwrap();
        fs::write(dir.join(MANIFEST), format!("{{\"id\":\"{slot}\"}}")).unwrap();
    }

    fn committed(stage: &Path) -> BTreeSet<String> {
        local_slots(stage).unwrap().committed
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

    #[test]
    fn local_slots_splits_committed_from_in_progress_and_skips_payloads() {
        let tmp = tempfile::tempdir().unwrap();
        write_slot(tmp.path(), "g/x/1", "a");
        fs::create_dir_all(tmp.path().join("g/x/2").join(PAYLOAD)).unwrap();
        // A manifest-named file inside a payload is not a slot.
        fs::write(tmp.path().join("g/x/1/payload/manifest.json"), "{}").unwrap();
        fs::write(tmp.path().join(BASELINE), "[]").unwrap();
        let s = local_slots(tmp.path()).unwrap();
        assert_eq!(s.committed, set(&["g/x/1"]));
        assert_eq!(s.in_progress, set(&["g/x/2"]));
    }

    #[test]
    fn stale_stage_sync_never_deletes_another_hosts_new_slot() {
        let f = fleet();
        write_slot(&f.a, "g/a/1", "a1");
        reconcile(&f.a, &f.remote).unwrap();
        reconcile(&f.b, &f.remote).unwrap();
        assert_eq!(committed(&f.b), set(&["g/a/1"]));

        // A adds a slot B has not seen; B then backs up from its stale stage
        // and syncs without any refresh first (the backup.run path).
        write_slot(&f.a, "g/a/2", "a2");
        reconcile(&f.a, &f.remote).unwrap();
        write_slot(&f.b, "g/b/1", "b1");
        reconcile(&f.b, &f.remote).unwrap();

        assert_eq!(committed(&f.remote.root), set(&["g/a/1", "g/a/2", "g/b/1"]));
        assert_eq!(committed(&f.b), set(&["g/a/1", "g/a/2", "g/b/1"]));
    }

    #[test]
    fn prunes_propagate_both_ways() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        write_slot(&f.a, "g/2", "2");
        reconcile(&f.a, &f.remote).unwrap();
        reconcile(&f.b, &f.remote).unwrap();

        // B's retention prunes g/1.
        fs::remove_dir_all(f.b.join("g/1")).unwrap();
        reconcile(&f.b, &f.remote).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/2"]));

        // A sees the prune on its next reconcile instead of resurrecting it.
        reconcile(&f.a, &f.remote).unwrap();
        assert_eq!(committed(&f.a), set(&["g/2"]));
        assert_eq!(committed(&f.remote.root), set(&["g/2"]));
    }

    #[test]
    fn failed_push_keeps_the_slot_and_retries() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        f.remote.fail_push.set(true);
        assert!(reconcile(&f.a, &f.remote).is_err());
        assert_eq!(committed(&f.a), set(&["g/1"]));
        f.remote.fail_push.set(false);
        reconcile(&f.a, &f.remote).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/1"]));
    }

    #[test]
    fn failed_pull_never_turns_unpulled_slots_into_remote_deletes() {
        let f = fleet();
        write_slot(&f.a, "g/a/1", "a1");
        reconcile(&f.a, &f.remote).unwrap();

        write_slot(&f.b, "g/b/1", "b1");
        f.remote.fail_pull.set(true);
        assert!(reconcile(&f.b, &f.remote).is_err());
        // A's slot is listed remotely but was never pulled to B: it must not
        // be in B's baseline, or the next reconcile would purge it.
        assert!(!read_baseline(&f.b).unwrap().contains("g/a/1"));

        f.remote.fail_pull.set(false);
        reconcile(&f.b, &f.remote).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/a/1", "g/b/1"]));
        assert_eq!(committed(&f.b), set(&["g/a/1", "g/b/1"]));
    }

    #[test]
    fn same_id_from_two_hosts_is_reported_not_overwritten() {
        let f = fleet();
        write_slot(&f.a, "g/1", "from-a");
        reconcile(&f.a, &f.remote).unwrap();
        write_slot(&f.b, "g/1", "from-b");
        let err = reconcile(&f.b, &f.remote).unwrap_err();
        assert!(err.contains("g/1"), "{err}");
        let read = |root: &Path| fs::read_to_string(root.join("g/1/payload/save.dat")).unwrap();
        assert_eq!(read(&f.remote.root), "from-a");
        assert_eq!(read(&f.b), "from-b");
        // Still flagged on the next pass rather than silently adopted.
        assert!(reconcile(&f.b, &f.remote).is_err());
    }

    #[test]
    fn identical_slot_is_adopted_when_the_baseline_was_lost() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        reconcile(&f.a, &f.remote).unwrap();
        fs::remove_file(f.a.join(BASELINE)).unwrap();
        reconcile(&f.a, &f.remote).unwrap();
        assert_eq!(read_baseline(&f.a).unwrap(), set(&["g/1"]));
    }

    #[test]
    fn in_progress_slot_is_never_pulled_into() {
        let f = fleet();
        write_slot(&f.a, "g/1", "theirs");
        reconcile(&f.a, &f.remote).unwrap();
        fs::create_dir_all(f.b.join("g/1").join(PAYLOAD)).unwrap();
        fs::write(f.b.join("g/1/payload/mine.dat"), "mine").unwrap();
        reconcile(&f.b, &f.remote).unwrap();
        assert!(!f.b.join("g/1/payload/save.dat").exists());
        assert!(!f.b.join("g/1").join(MANIFEST).exists());
    }

    #[test]
    fn an_emptied_remote_is_refused_and_the_stage_survives() {
        let f = fleet();
        write_slot(&f.a, "g/1", "1");
        reconcile(&f.a, &f.remote).unwrap();
        fs::remove_dir_all(f.remote.root.join("g")).unwrap();
        assert!(reconcile(&f.a, &f.remote).is_err());
        assert_eq!(committed(&f.a), set(&["g/1"]));
    }

    /// The real rclone command lines (filters over stdin, two-pass copy, lsf
    /// listing, purge, check) against a plain directory standing in for the
    /// share. Needs `rclone` on PATH or `ORCA_RCLONE_BIN`.
    #[test]
    #[ignore = "needs an rclone binary"]
    fn rclone_reconcile_against_a_local_dir() {
        let bin = std::env::var("ORCA_RCLONE_BIN")
            .ok()
            .or_else(|| plugin_toolkit::path::which("rclone"))
            .expect("rclone on PATH or ORCA_RCLONE_BIN");
        let f = fleet();
        let remote = |pass: &str| RcloneRemote {
            rclone: Rclone::connect(PathBuf::from(&bin), "h", "u", pass).unwrap(),
            root: f.remote.root.to_string_lossy().into_owned(),
        };
        let r = remote("pw");
        write_slot(&f.a, "g/[EU] a/1", "a1");
        write_slot(&f.a, "g/[EU] a/2", "a2");
        reconcile(&f.a, &r).unwrap();
        reconcile(&f.b, &r).unwrap();
        assert_eq!(committed(&f.b), set(&["g/[EU] a/1", "g/[EU] a/2"]));

        fs::remove_dir_all(f.b.join("g/[EU] a/1")).unwrap();
        write_slot(&f.b, "g/b/1", "b1");
        reconcile(&f.b, &r).unwrap();
        reconcile(&f.a, &r).unwrap();
        assert_eq!(committed(&f.remote.root), set(&["g/[EU] a/2", "g/b/1"]));
        assert_eq!(committed(&f.a), set(&["g/[EU] a/2", "g/b/1"]));

        write_slot(&f.a, "g/c/1", "from-a");
        write_slot(&f.b, "g/c/1", "from-b");
        reconcile(&f.a, &r).unwrap();
        assert!(reconcile(&f.b, &r).is_err());
        assert!(r.purge("g/missing").is_ok());
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
        reconcile(a.path(), &remote).unwrap();
        reconcile(b.path(), &remote).unwrap();
        assert!(committed(b.path()).contains("live/1"));
        fs::remove_dir_all(a.path().join("live/1")).unwrap();
        write_slot(a.path(), "live/2", "two");
        reconcile(a.path(), &remote).unwrap();
        assert!(!remote.list().unwrap().contains("live/1"));
        remote.purge("live/2").unwrap();
    }
}
