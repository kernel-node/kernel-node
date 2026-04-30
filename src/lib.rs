pub mod daemonize;
pub mod ipc;
pub mod kernel_util;
pub mod peer;

capnp::generated_code!(pub mod server_capnp);
capnp::generated_code!(pub mod wallet_capnp);
