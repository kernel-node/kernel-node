mod common;

use std::collections::HashMap;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{Block, BlockHash};
use common::scripted_peer::{receive, send, version};
use common::{start_bitcoind, TestNode};

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS: usize = 10;

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
