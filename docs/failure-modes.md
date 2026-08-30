# SMB/CIFS failure modes

Field notes on how CIFS mounts actually break, and what this plugin does about
each. Every mode below was observed on a real fleet; the behaviour described
under "What the plugin does" is what the managed mount tooling is expected to
carry.

The modes are independent and routinely co-occur during a NAS outage or
failover. Two of them — modes 2 and 3 — are cases where a mount that *succeeds*
is still wrong: the kernel reports success while the data behind it is stale,
incomplete, or served under the wrong identity.

---

## 1. Stale CIFS mount after a server-side SMB drop

**Symptom.** The mount table still lists the share, but the mountpoint is dead:

```
$ findmnt /mnt/data
TARGET    SOURCE        FSTYPE OPTIONS
/mnt/data //host/share  cifs   rw,...

$ ls /mnt/data
ls: cannot access '/mnt/data': No such file or directory

$ ls -la /mnt
d?????????  ? ? ? ?            ? data
```

The `d?????????` line — every field a `?` — is the tell: the kernel cannot even
`stat` the directory it is holding a mount for.

**Cause.** The mount is `soft`, and its SMB session was torn down server-side
while the mount was live — for example the NAS's shfs/FUSE union crashed out
from under the share. A `soft` CIFS mount gives up on the dead session rather
than blocking forever, but it never renegotiates a new one. The mount table
entry survives; the thing it points at does not.

**Why presence is not liveness.** The share is still in `findmnt -t cifs`, so any
check that trusts the mount table alone reports it healthy. It is not — the mount
is a corpse the kernel has not buried.

**What the plugin does / should do.** Liveness requires two facts, not one:

- The path is a CIFS mount — `findmnt -t cifs <mp>`.
- The path actually answers — `timeout <N> stat <mp>` returns zero. A live mount
  passes; a stale one errors out (or the `timeout` fires), and that is the
  signal.

Recovery is a forced remount, not a plain `mount`: `umount -lf <mp>` to detach
the wedged mount, then re-mount from the managed configuration. A lazy-forced
unmount is required because the stale mount still holds references that a plain
`umount` refuses to release.

---

## 2. Failover to a replica silently serves incomplete data

**Symptom.** After failover from the primary NAS to a replica, the share mounts
cleanly and older files read fine — but recently-added files are simply not
there. Consumers that indexed them against the primary report them as
"Unavailable" (Plex, for instance, shows the item but cannot play it).

**Cause.** The replica only holds content through its last replication sync. The
newest files exist only on the primary and were never copied before it went
away. The mount is healthy by every local check; the data behind it is a
point-in-time subset.

**Why this is worse than a hard failure.** A dead mount announces itself. A
replica that is merely *behind* looks identical to the authoritative source —
same paths, same permissions, same successful `stat` — right up until something
reaches for a file that only ever lived on the primary.

**What the plugin does / should do.** Treat replica-serving as a *degraded*
state, not an equivalent one:

- The mount succeeded, but it is not authoritative — surface that distinction
  rather than reporting a plain success.
- Prefer failback to the primary as soon as it is healthy again, instead of
  settling on the replica.
- Warn that the newest data may be absent, so a consumer's "file missing" is
  read as expected degradation rather than corruption.

---

## 3. A cached guest session poisons re-authentication

**Symptom.** After a NAS reboot or outage, re-mounting an authenticated share
fails with permission denied even though the credentials are correct:

```
$ mount -t cifs //host/private /mnt/private -o ...
mount error(13): Permission denied
```

The same credentials succeed when tested directly against the server. The
mount table looks clean, but the CIFS debug state gives it away:

```
$ cat /proc/fs/cifs/DebugData
...
Sessions:
1) Address: <host> ...
   Session Status: 1 Guest
```

**Cause.** By default the Linux CIFS client shares one session and socket per
`(server, user)` pair across mounts. During the outage a mount fell back to a
guest session; that guest session stays cached, and the next mount of an
authenticated share to the same server reuses it. The tree connect then runs as
guest against a share that guests may not touch, and the server returns
`error(13)` — not because auth failed, but because the wrong (guest) session was
reused before auth ever ran.

**What the plugin does / should do.** Mount with `nosharesock`. That option
gives every mount its own session and socket instead of pooling them, so a
poisoned guest session from a prior fallback cannot be inherited by a fresh
authenticated mount. This makes mounts immune to guest-session poisoning across
failover and failback.

On the fleet's Proxmox hosts `nosharesock` was added to the `OPTS` in
`/usr/local/sbin/orca-smb-mount`. The managed mount tooling should carry it by
default rather than relying on an operator to remember it after the first
incident.

---

## Operator checklist

After a NAS reboot or failover, on every client that did **not** also reboot:

1. **Do not trust the mount table.** `findmnt -t cifs <mp>` proving the mount
   exists says nothing about whether it answers. Follow it with
   `timeout <N> stat <mp>` and treat any non-zero result — or a `d?????????`
   line in `ls -la` — as a stale mount to force-remount (`umount -lf`, then
   re-mount).
2. **Assume a replica is behind.** If the share failed over, expect the newest
   files to be missing until failback. A consumer reporting a recent file as
   unavailable is the mode-2 signature, not corruption.
3. **Check for a cached guest session** when an authenticated re-mount returns
   `error(13)` despite correct credentials: `cat /proc/fs/cifs/DebugData` and
   look for `Session Status: 1 Guest`. Re-mount with `nosharesock` to force a
   fresh session.
