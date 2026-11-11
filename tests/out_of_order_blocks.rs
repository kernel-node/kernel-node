mod common;

use std::collections::HashMap;
use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::block::Header;
use bitcoin::consensus::{serialize, Decodable};
use bitcoin::io::from_std_mut;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::{Block, BlockHash, Network};
use common::{start_bitcoind, TestNode};

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS: usize = 10;
const PROTOCOL_VERSION: u32 = 70016;

#[test]
fn connects_a_block_that_arrives_before_its_parent() {
    let core = start_bitcoind();
    let address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(BLOCKS, &address)
        .expect("mine blocks");
    let height = core.client.get_block_count().expect("block count").0;
    let blocks: Vec<Block> = (1..=height)
        .map(|block_height| {
            let hash = core
                .client
                .get_block_hash(block_height)
                .expect("block hash")
                .0
                .parse::<BlockHash>()
                .expect("parse block hash");
            core.client.get_block(hash).expect("block")
        })
        .collect();
    let hash = core.client.best_block_hash().expect("best block hash");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let _ = serve_in_reverse(listener, blocks, height);
    });

    let node = TestNode::start_connected(peer_addr, None);
    node.wait_for_tip(height, hash, SYNC_TIMEOUT);

    node.stop();
    peer.join().unwrap();
}

fn serve_in_reverse(listener: TcpListener, blocks: Vec<Block>, height: u64) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    send(&mut stream, NetworkMessage::Version(version(height)))?;
    send(&mut stream, NetworkMessage::Verack)?;
    let headers: Vec<Header> = blocks.iter().map(|block| block.header).collect();
    let blocks: HashMap<BlockHash, Block> = blocks
        .into_iter()
        .map(|block| (block.block_hash(), block))
        .collect();
    loop {
        match receive(&mut reader)? {
            NetworkMessage::GetHeaders(_) => {
                send(&mut stream, NetworkMessage::Headers(headers.clone()))?
            }
            NetworkMessage::GetData(inventory) => {
                for item in inventory.iter().rev() {
                    let Inventory::WitnessBlock(hash) = item else {
                        continue;
                    };
                    send(&mut stream, NetworkMessage::Block(blocks[hash].clone()))?;
                }
            }
            NetworkMessage::Ping(nonce) => send(&mut stream, NetworkMessage::Pong(nonce))?,
            // Answering getblocks would let the node fetch a dropped block again.
            _ => {}
        }
    }
}

fn version(height: u64) -> VersionMessage {
    let unused = Address::new(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ServiceFlags::NONE,
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: i64::try_from(now.as_secs()).unwrap(),
        receiver: unused.clone(),
        sender: unused,
        nonce: 0,
        user_agent: "/scripted-peer/".to_string(),
        start_height: i32::try_from(height).unwrap(),
        relay: false,
    }
}

fn send(stream: &mut TcpStream, payload: NetworkMessage) -> io::Result<()> {
    let message = RawNetworkMessage::new(Network::Regtest.magic(), payload);
    stream.write_all(&serialize(&message))
}

fn receive(reader: &mut BufReader<TcpStream>) -> io::Result<NetworkMessage> {
    let message =
        RawNetworkMessage::consensus_decode(from_std_mut(reader)).map_err(io::Error::other)?;
    Ok(message.into_payload())
}
