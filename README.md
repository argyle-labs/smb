<p align="center">
  <img src="assets/icon-256.png" width="120" alt="smb" />
</p>

# smb — orca storage plugin

An [orca](https://github.com/argyle-labs/orca) **backend-only** plugin. It
carries zero `#[orca_tool]`s; instead it registers an SMB/CIFS `StorageBackend`
into orca's generic `storage` domain across the cdylib FFI seam.

## What it does

orca treats every storage provider — NFS/SMB network shares, Proxmox-managed
disk storage, … — through one trait + one registry. This plugin contributes the
SMB/CIFS facts and capabilities:

- **`list`** — read the live mount table and report SMB/CIFS shares
  (`cifs`/`smb3`/`smbfs`).
- **`unmount`** — unmount a target via `umount`.

The crate also exposes the SMB-specific primitives a richer caller can drive
directly — `mount` (`mount.cifs` on Linux, `mount_smbfs` on macOS), share
discovery via `smbclient -L`, credentials, and a time-bounded health probe —
but the thin storage-domain descriptor only advertises `list` + `unmount`,
since the domain's single-id `mount` op can't supply a server + share +
credentials.

When orca's `plugin-loader` `dlopen`s the built cdylib, a successful load
registers an `smb` backend into the process-global storage registry. Every call
against that backend is a host-side `StorageProxy` that marshals its args to
JSON and calls back into this library's `invoke()` under the
`storage.__backend.smb.*` namespace.

## Building

```sh
# cdylib artifact the loader dlopens
cargo build --lib

# in-crate test harness
cargo test
```

A checked-out `argyle-labs/orca` at `../orca` resolves the `plugin-toolkit`
dependency locally via the `[patch]` in `.cargo/config.toml`. Otherwise it
resolves from orca's `dev` branch.

## Single dependency

Per orca's plugin contract, this plugin reaches the entire orca system —
infra and the `storage` domain (`plugin_toolkit::storage`) — through
`plugin-toolkit` alone. The only other dependency is `abi_stable`, required
because `#[export_root_module]` emits bare `::abi_stable` paths at the cdylib
FFI boundary.
