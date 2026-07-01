<p align="center">
  <img src="assets/icon-256.png" width="120" alt="smb" />
</p>

# smb

Registers an SMB/CIFS `StorageBackend` — it mounts existing SMB shares into orca's storage domain.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (storage-backend).

This is a **backend/adapter** — it has no service of its own; it wires an existing system into orca.

---

## Run it without orca

There's nothing to deploy: this plugin drives software you already run (upstream: <https://www.samba.org/>). Install/configure that directly, then register it with orca.


## With orca

orca drives this plugin through its generic surface — rich, smb-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `assets/` — plugin icon.
