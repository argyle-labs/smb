<p align="center">
  <img src="assets/icon-256.png" width="120" alt="smb" />
</p>

# smb

Registers an SMB/CIFS `StorageBackend` — it mounts existing SMB shares into orca's storage domain — and an `smb` backup target that stores backups on an SMB share over rclone, with no mount and no root.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (storage-backend).

This is a **backend/adapter** — it has no service of its own; it wires an existing system into orca.

---

## Run it without orca

There's nothing to deploy: this plugin drives software you already run (upstream: <https://www.samba.org/>). Install/configure that directly, then register it with orca.


## With orca

orca drives this plugin through its generic surface — rich, smb-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `SmbBackend` `StorageBackend` descriptor + `validate_spec` / `mount` / `unmount` / `list_shares`.
- `src/backup_target.rs` — the `smb` backup target: config (`backup`/`target:smb:<name>`), and the slot-level stage↔share reconcile.
- `src/rclone.rs` — rclone resolution/provisioning (pinned, checksum-verified) and the rclone calls.
- `assets/` — plugin icon.
