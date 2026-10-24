mod common;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use addrman::Record;
use bitcoin::p2p::{address::AddrV2, ServiceFlags};
use common::{start_bitcoind, TestNode};
use kernel_node::net::addr::{AddrTable, AddrTableExt};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[test]
fn connects_to_peer_from_peers_file() {
    let core = start_bitcoind();
    let p2p = core.params.p2p_socket.unwrap();

    let tempdir = tempfile::tempdir().unwrap();
    let mut table = AddrTable::new();
    table.add(&Record::new(
        AddrV2::Ipv4(*p2p.ip()),
        p2p.port(),
        ServiceFlags::NETWORK,
        &IpAddr::V4(*p2p.ip()),
    ));
    table.save(&tempdir.path().join("peers.bin")).unwrap();

    let node = TestNode::start_in(tempdir, &[], None);

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let count = core
            .client
            .get_connection_count()
            .expect("query bitcoind connection count")
            .0;
        if count >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "node did not connect to bitcoind from peers.bin within {CONNECT_TIMEOUT:?}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }

    node.stop();
}
