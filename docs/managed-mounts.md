# Managed mounts — the orca-native way (never hand-roll)

Companion to `failure-modes.md`. That doc describes how a CIFS/SMB mount *breaks*.
This one states the operating rule that keeps you out of trouble in the first
place, and is the source for the **agent/skill this plugin ships to Claude**
(`orca install` installs it, so the assistant always drives mounts the orca-native
way instead of falling back to shell).

## The rule

**An SMB/CIFS mount on a fleet host is an orca-managed object. Manage it through
orca's storage surface — never through `fstab`, ad-hoc `mount -t cifs`, or a
hand-rolled failover script.**

- The **share** carries the *failover truth*: its route-set lists every server
  that can satisfy the mount (primary + replica[s] + alternate transports such as
  a mesh/Tailscale address), which is active and which are standby.
- A **mount placement** on a host references a share. Orca's convergence loop
  keeps that placement mounted on whichever route is currently live, and moves it
  to a standby route on failure (primary→replica proven ~100s on this fleet).
- A consumer just reads/writes the mountpoint (e.g. `/mnt/backups`). It does not
  know or care which server is behind it. Orca owns the switching.

## How to operate it (orca MCP / CLI surface)

| Intent | Use |
| --- | --- |
| See mounts on hosts | `storage_mount_list` / `storage_mount_detail` |
| See the failover route-set | `storage_share_list` / `storage_share_detail` |
| Add/point a mount at a share | `storage_mount_create` / `storage_mount_update` |
| Define/adjust the route-set (failover truth) | `storage_share_*` |
| Fix share ACLs/perms | `storage_share_repair-permissions` |

To change *where* a mount lives or *how it fails over*, edit the **share's
route-set**, not the client. To place the mount on a new host, create a **mount
placement** referencing the share.

## Anti-pattern (a real mistake this plugin exists to prevent)

Symptom that tempts you: the primary is degraded, so you reach for
`mount -t cifs //<replica>/backups /mnt/x -o cred=…`, add an `/etc/fstab` line,
and write a little `pick_root()` shell that tries primary then replica.

Why it's wrong:

- You now have **two** sources of failover truth — yours and orca's — and they
  fight. Orca's convergence will reconcile the mount back and can *remove* your
  hand-mounted one out from under a running consumer. (Observed: a stray
  `umount -l` of what looked like a hand mount actually removed the orca-managed
  one; orca then reconciled it back.)
- Your script re-implements, worse, what the share route-set already does
  (health-checked, drain-then-remount, non-empty-replica guard, no-flap
  return-to-primary).
- `fstab`/`mount -a` only knows fstab; orca's recover path partitions against its
  own declared placements. The two views diverge silently.

Correct move: if the mount should be able to fail to that replica, **add the
replica route to the share** and let convergence use it. If a host needs the
mount, **create a placement** referencing the share. Nothing goes in `fstab`.

## Notes that bite (SMB-specific)

- **Per-route credentials differ — this is the classic SMB trap.** The replica
  server may not share the primary's password for the same service account. A
  single hand-rolled `mount -t cifs` with one credential returns
  `STATUS_LOGON_FAILURE` against the other server. The share's route-set carries
  per-route auth; that's the whole point of not hand-mounting. (Live example on
  this fleet: the replica NAS's `orca` SMB password differs from the primary's.)
- **Don't trust the mount table.** `findmnt -t cifs <mp>` proving a mount exists
  says nothing about whether I/O completes (see `failure-modes.md` — a CIFS mount
  can be present-but-wedged after a server flap). Health is a timed read, not a
  table lookup; orca's probe does this, a hand script usually doesn't.
- **Stale bind mounts after a server flap.** A container bind-mounting the CIFS
  path can `ENOENT` after the server recovers because the *bind* still points at
  the old inode; the fix is to restart the consumer, which orca's recover-bounce
  handles.
- **A non-orca host is the only exception.** A box that is *not* an orca peer
  genuinely can't use the managed surface; there, a plain mount is acceptable and
  should be documented AS an exception, not copied as the norm.
