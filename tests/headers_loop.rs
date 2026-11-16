mod common;

use std::io::{self, BufReader};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::BlockHash;
use common::scripted_peer::{receive, send, version};
use common::TestNode;

const WATCH_FOR: Duration = Duration::from_secs(5);

#[test]
fn stops_asking_a_peer_with_no_headers() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (requests_tx, requests_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = answer_with_nothing(listener, requests_tx);
    });

    let node = TestNode::start_connected(peer_addr, None);
    thread::sleep(WATCH_FOR);
    let requests: Vec<&str> = requests_rx.try_iter().collect();
    assert_eq!(requests, vec!["getheaders"]);

    node.stop();
}

fn answer_with_nothing(
    listener: TcpListener,
    requests: mpsc::Sender<&'static str>,
) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    send(&mut stream, NetworkMessage::Version(version(0)))?;
    send(&mut stream, NetworkMessage::Verack)?;
    loop {
        let message = receive(&mut reader)?;
        match message {
            NetworkMessage::GetHeaders(_) => {
                let _ = requests.send(message.cmd());
                send(&mut stream, NetworkMessage::Headers(vec![]))?;
            }
            NetworkMessage::GetBlocks(_) => {
                let _ = requests.send(message.cmd());
                let unknown = BlockHash::from_byte_array([1; 32]);
                send(
                    &mut stream,
                    NetworkMessage::Inv(vec![Inventory::Block(unknown)]),
                )?;
            }
            NetworkMessage::Ping(nonce) => send(&mut stream, NetworkMessage::Pong(nonce))?,
            _ => {}
        }
    }
}
