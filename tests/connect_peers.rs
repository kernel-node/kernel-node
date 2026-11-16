mod common;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::TestNode;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn connects_to_each_peer_sharing_an_ip() {
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let mut peers: Vec<SocketAddr> = Vec::new();
    for _ in 0..2 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        peers.push(addr);
        let accepted_tx = accepted_tx.clone();
        thread::spawn(move || {
            if listener.accept().is_ok() {
                let _ = accepted_tx.send(addr);
            }
        });
    }

    let peer_args: Vec<String> = peers.iter().map(SocketAddr::to_string).collect();
    let node = TestNode::start_connected_to(&peer_args, None);
    let mut accepted: Vec<SocketAddr> = (0..2)
        .map(|_| {
            accepted_rx
                .recv_timeout(CONNECT_TIMEOUT)
                .expect("node did not connect to every peer")
        })
        .collect();
    accepted.sort();
    peers.sort();
    assert_eq!(accepted, peers);

    node.stop();
}
