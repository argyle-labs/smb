//! Dynamic (subprocess) entrypoint for the smb plugin.
//!
//! Serves this plugin over the orca socket via the typed `Plugin` builder: the
//! `smb` storage backend plus the `smb` backup target. The plugin is a
//! `[[bin]]`, owns no runtime, and reaches orca only through the socket.
plugin_toolkit::instrument::bootstrap!();
use plugin_toolkit::plugin::Plugin;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("smb")
        .version(env!("CARGO_PKG_VERSION"))
        .storage(smb::SmbBackend::new("smb"))
        .backend(
            smb::backup_target::backend_def(),
            Box::new(smb::backup_target::dispatcher),
        )
        .serve()
}
