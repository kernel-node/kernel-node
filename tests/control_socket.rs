mod common;

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use common::TestNode;

// Past the Unix socket path limit, 104 bytes on macOS and 108 on Linux.
const LONG_NAME_LEN: usize = 120;
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[test]
fn stops_when_the_control_socket_cannot_open() {
    let tempdir = tempfile::tempdir().unwrap();
    let datadir = tempdir.path().join("d".repeat(LONG_NAME_LEN));
    let mut node = Command::new(env!("CARGO_BIN_EXE_node"))
        .args(["--network", "regtest", "--connect", "127.0.0.1:1"])
        .arg("--datadir")
        .arg(&datadir)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + EXIT_TIMEOUT;
    while node.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            node.kill().unwrap();
            panic!("node kept running without its control socket");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[test]
fn stops_on_ctrl_c() {
    TestNode::start().interrupt();
}
