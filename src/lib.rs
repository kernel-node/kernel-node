pub mod daemonize;
pub mod ipc;
pub mod kernel_util;
pub mod peer;
pub mod peer_manager;

capnp::generated_code!(pub mod server_capnp);
