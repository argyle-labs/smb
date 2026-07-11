//! Dynamic (subprocess) entrypoint for the smb plugin.
//!
//! The toolkit's `serve_storage_plugin!` emits `fn main`, serving this plugin over the orca
//! socket. Dynamic replacement for the retired cdylib export — the plugin is a
//! `[[bin]]`, owns no runtime, and reaches orca only through the socket.
plugin_toolkit::serve_storage_plugin! {
    name: "smb",
    target_compat: "any",
    backend: smb::SmbBackend::new("smb"),
}
