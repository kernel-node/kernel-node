mod common;

use std::io::{self, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::ServiceFlags;
use common::scripted_peer::{receive, send, version};
use common::TestNode;
use kernel_node::net::manager::FEELER_INTERVAL;

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

#[test]
fn connects_to_nothing_else() {
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let gossiped = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    let gossiped_addr = gossiped.local_addr().unwrap();
    let connect = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let connect_addr = connect.local_addr().unwrap();
    for listener in [gossiped, connect] {
        let accepted_tx = accepted_tx.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let addr = stream.local_addr().unwrap();
                let _ = accepted_tx.send(addr);
                if addr == connect_addr {
                    thread::spawn(move || serve_and_gossip(stream, gossiped_addr));
                }
            }
        });
    }

    let node = TestNode::start_connected(connect_addr, None);
    thread::sleep(FEELER_INTERVAL + Duration::from_secs(5));
    let accepted: Vec<SocketAddr> = accepted_rx.try_iter().collect();
    assert_eq!(accepted, vec![connect_addr]);

    node.stop();
}

fn serve_and_gossip(mut stream: TcpStream, gossiped: SocketAddr) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    send(&mut stream, NetworkMessage::Version(version(0)))?;
    send(&mut stream, NetworkMessage::Verack)?;
    let SocketAddr::V6(gossiped) = gossiped else {
        unreachable!("the gossiped listener is bound to an IPv6 address")
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    send(
        &mut stream,
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time: u32::try_from(now.as_secs()).unwrap(),
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv6(*gossiped.ip()),
            port: gossiped.port(),
        }]),
    )?;
    loop {
        match receive(&mut reader)? {
            NetworkMessage::GetHeaders(_) => send(&mut stream, NetworkMessage::Headers(vec![]))?,
            NetworkMessage::Ping(nonce) => send(&mut stream, NetworkMessage::Pong(nonce))?,
            _ => {}
        }
    }
}
