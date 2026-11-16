mod common;

use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Instant;

use bitcoin::p2p::message::NetworkMessage;
use common::scripted_peer::{send, version};
use common::TestNode;
use kernel_node::net::peer::PEER_STALL_TIMEOUT;
use p2p::net::READ_TIMEOUT;

#[test]
fn drops_a_peer_that_stops_answering() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        send(&mut stream, NetworkMessage::Version(version(0)))?;
        send(&mut stream, NetworkMessage::Verack)?;
        let silent_since = Instant::now();
        io::copy(&mut stream, &mut io::sink())?;
        io::Result::Ok(silent_since.elapsed())
    });

    let node = TestNode::start_connected(peer_addr, None);
    let silent_for = peer.join().unwrap().unwrap();
    assert!(
        (PEER_STALL_TIMEOUT..READ_TIMEOUT).contains(&silent_for),
        "dropped after {silent_for:?}, not between the stall and read timeouts"
    );

    node.stop();
}
