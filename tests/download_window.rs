mod common;

use std::collections::HashMap;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{Block, BlockHash};
use common::scripted_peer::{receive, regtest_chain, send, version};
use common::TestNode;
use kernel_node::net::peer::BLOCK_DOWNLOAD_WINDOW;

const BLOCKS_PAST_WINDOW: u64 = 100;
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const WINDOW_FULL_FOR: Duration = Duration::from_secs(2);

struct Chain {
    height: u64,
    headers: Vec<Header>,
    blocks: HashMap<BlockHash, (u64, Block)>,
    first: BlockHash,
    withholder: Mutex<Option<TcpStream>>,
    first_withheld: AtomicBool,
    first_sent: AtomicBool,
    highest_requested_before_first: AtomicU64,
}

impl Chain {
    fn new(blocks: Vec<Block>) -> Self {
        Chain {
            height: u64::try_from(blocks.len()).unwrap(),
            headers: blocks.iter().map(|block| block.header).collect(),
            first: blocks[0].block_hash(),
            blocks: (1..)
                .zip(blocks)
                .map(|(height, block)| (block.block_hash(), (height, block)))
                .collect(),
            withholder: Mutex::new(None),
            first_withheld: AtomicBool::new(false),
            first_sent: AtomicBool::new(false),
            highest_requested_before_first: AtomicU64::new(0),
        }
    }

    fn block_to_send(&self, hash: BlockHash, stream: &TcpStream) -> io::Result<Option<&Block>> {
        let (height, block) = &self.blocks[&hash];
        if !self.first_sent.load(Ordering::SeqCst) {
            self.highest_requested_before_first
                .fetch_max(*height, Ordering::SeqCst);
        }
        if hash == self.first {
            if !self.first_withheld.swap(true, Ordering::SeqCst) {
                *self.withholder.lock().unwrap() = Some(stream.try_clone()?);
                return Ok(None);
            }
            self.first_sent.store(true, Ordering::SeqCst);
        }
        Ok(Some(block))
    }

    fn window_is_full(&self, window: u64) -> bool {
        self.withholder.lock().unwrap().is_some()
            && self.highest_requested_before_first.load(Ordering::SeqCst) >= window
    }

    fn disconnect_withholder(&self) {
        if let Some(withholder) = self.withholder.lock().unwrap().take() {
            let _ = withholder.shutdown(Shutdown::Both);
        }
    }
}

#[test]
fn waits_at_the_window_for_a_withheld_block() {
    let window = u64::try_from(BLOCK_DOWNLOAD_WINDOW).unwrap();
    let blocks = regtest_chain(window + BLOCKS_PAST_WINDOW);
    let tip = blocks.last().unwrap().block_hash();
    let chain = Arc::new(Chain::new(blocks));

    let mut peer_addrs = Vec::new();
    let mut peers = Vec::new();
    for _ in 0..2 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer_addrs.push(listener.local_addr().unwrap().to_string());
        let chain = Arc::clone(&chain);
        peers.push(thread::spawn(move || {
            let _ = serve(listener, &chain);
        }));
    }

    let node = TestNode::start_connected_to(&peer_addrs, None);
    let deadline = Instant::now() + SYNC_TIMEOUT;
    while !chain.window_is_full(window) {
        assert!(Instant::now() < deadline, "the window never filled");
        thread::sleep(POLL_INTERVAL);
    }
    // Long enough to catch requests past the window.
    thread::sleep(WINDOW_FULL_FOR);
    chain.disconnect_withholder();

    node.wait_for_tip(chain.height, tip, SYNC_TIMEOUT);
    assert_eq!(
        chain.highest_requested_before_first.load(Ordering::SeqCst),
        window
    );

    node.stop();
    for peer in peers {
        peer.join().unwrap();
    }
}

fn serve(listener: TcpListener, chain: &Chain) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    send(&mut stream, NetworkMessage::Version(version(chain.height)))?;
    send(&mut stream, NetworkMessage::Verack)?;
    loop {
        match receive(&mut reader)? {
            NetworkMessage::GetHeaders(_) => {
                send(&mut stream, NetworkMessage::Headers(chain.headers.clone()))?
            }
            NetworkMessage::GetData(inventory) => {
                for item in inventory {
                    let Inventory::WitnessBlock(hash) = item else {
                        continue;
                    };
                    if let Some(block) = chain.block_to_send(hash, &stream)? {
                        send(&mut stream, NetworkMessage::Block(block.clone()))?;
                    }
                }
            }
            NetworkMessage::Ping(nonce) => send(&mut stream, NetworkMessage::Pong(nonce))?,
            // Ignoring getblocks leaves only the idle check to retry.
            _ => {}
        }
    }
}
