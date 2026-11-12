use std::{
    collections::{HashSet, VecDeque},
    fmt, iter,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

use bitcoin::{
    hashes::Hash,
    p2p::{
        address::{AddrV2, AddrV2Message},
        message::NetworkMessage,
        message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory},
        ServiceFlags,
    },
};
use bitcoin::{BlockHash, Network};
use bitcoinkernel::{
    core::BlockHashExt, BlockTreeEntry, ChainstateManager, Context, ProcessBlockHeaderResult,
    ProcessBlockResult,
};
use log::{debug, info, warn};
use p2p::{
    handshake::{ConnectionConfig, ProtocolVersion},
    net::{ConnectionReader, ConnectionWriter, READ_TIMEOUT},
};

use crate::{
    ext::{CrateBlockExt, CrateHeaderExt},
    logging::Category,
    net::{addr::Destination, manager, socks5::Socks5Proxy},
};

const PROTOCOL_VERSION: ProtocolVersion = 70015;
const MAX_LOCATOR_HASHES: usize = 101;
const DOWNLOAD_BATCH_SIZE: usize = 16;
const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct DownloadState {
    queue: VecDeque<BlockHash>,
    in_flight: HashSet<BlockHash>,
    received: HashSet<BlockHash>,
}

impl DownloadState {
    fn pop_batch(&mut self, batch_size: usize) -> Vec<BlockHash> {
        let mut batch = Vec::with_capacity(batch_size);
        while batch.len() < batch_size {
            let Some(hash) = self.queue.pop_front() else {
                break;
            };
            if self.in_flight.insert(hash) {
                batch.push(hash);
            }
        }
        batch
    }

    fn claim(&mut self, hashes: Vec<BlockHash>) -> Vec<BlockHash> {
        hashes
            .into_iter()
            .filter(|hash| self.in_flight.insert(*hash))
            .collect()
    }

    fn receive(&mut self, hash: BlockHash) -> bool {
        if !self.in_flight.remove(&hash) {
            return false;
        }
        self.received.insert(hash);
        true
    }

    fn requeue_unreceived(&mut self, inventory: &HashSet<BlockHash>) {
        if inventory.is_empty() {
            return;
        }
        for hash in inventory {
            self.in_flight.remove(hash);
            self.queue.push_front(*hash);
        }
        debug!(target: Category::NET, "Re-enqueued {} unreceived blocks", inventory.len());
    }

    fn forget_connected(&mut self, active_from_tip: impl IntoIterator<Item = BlockHash>) {
        for hash in active_from_tip {
            if !self.received.remove(&hash) {
                break;
            }
        }
    }
}

pub struct NodeState {
    pub addr_tx: mpsc::Sender<(AddrV2, Vec<AddrV2Message>)>,
    pub context: Arc<Context>,
    pub chainman: Arc<ChainstateManager>,
    pub download: Mutex<DownloadState>,
    pub block_tx: mpsc::SyncSender<bitcoinkernel::Block>,
}

impl NodeState {
    pub fn update_received(&self, block: &bitcoinkernel::Block, result: ProcessBlockResult) {
        let mut state = self.download.lock().unwrap();
        if result.is_rejected() {
            state
                .received
                .remove(&BlockHash::from_byte_array(block.hash().into()));
        }
        let tip = self.chainman.active_chain().tip();
        state.forget_connected(
            iter::successors(Some(tip), |entry| entry.prev())
                .map(|entry| BlockHash::from_byte_array(entry.block_hash().to_bytes())),
        );
    }
}

/// State Machine for setting up a connection and getting blocks from a peer
///
/// ```text
///                       [*]
///                        │
///                        ▼
///              ┌─────────────────┐   got 2000 headers:
///         ┌───▶│ AwaitingHeaders │──┐  ask for the next batch
///         │    └─────────────────┘◀─┘
///         │                 │
///         │                 │ header sync done: build the queue,
///         │                 │ then take the first batch
///         │                 ▼
///         │    ┌─────────────────┐   block arrives (batch not done), or
///         │    │  AwaitingBlock  │──┐  batch done + queue has more:
///         │    └─────────────────┘◀─┘  take the next batch
///         │       ▲         │
///         │  inv/ │         │ batch done AND queue empty
///         │  hdrs │         ▼
///         │    ┌─────────────────┐   nothing to claim: ask again
///         └────│   AwaitingInv   │──┐
///              └─────────────────┘◀─┘
/// ```
///
/// The left edge (AwaitingInv ─▶ AwaitingHeaders) is the unconnecting-headers
/// path: a peer's announced headers don't connect, so we resync headers.
#[derive(Default)]
pub enum PeerStateMachine {
    #[default]
    AwaitingHeaders,
    AwaitingInv,
    AwaitingBlock(AwaitingBlock),
}

pub struct AwaitingBlock {
    pub peer_inventory: HashSet<bitcoin::BlockHash>,
}

fn build_block_locators(tip: BlockTreeEntry<'_>) -> Vec<BlockHash> {
    let height = tip.height();
    assert!(height >= 0);
    let mut locators = Vec::with_capacity(MAX_LOCATOR_HASHES);
    let mut current_height = height;
    let mut step = 1;
    loop {
        let entry = tip
            .ancestor(current_height)
            .expect("height is between zero and the tip height");
        let hash = BlockHash::from_byte_array(entry.block_hash().to_bytes());
        locators.push(hash);
        if current_height == 0 || locators.len() >= MAX_LOCATOR_HASHES {
            break;
        }
        current_height = (current_height - step).max(0);
        if locators.len() > 10 {
            step *= 2;
        }
    }
    locators
}

fn populate_download_queue(chainman: &ChainstateManager, download: &Mutex<DownloadState>) {
    if !download.lock().unwrap().queue.is_empty() {
        return;
    }
    let active = chainman.active_chain();
    let best = match chainman.best_entry() {
        Some(entry) => entry,
        None => return,
    };
    let best_height = best.height();
    let mut hashes = Vec::new();
    let mut current = best;
    let fork_point = loop {
        if active.contains(&current) {
            break BlockHash::from_byte_array(current.block_hash().to_bytes());
        }
        hashes.push(BlockHash::from_byte_array(current.block_hash().to_bytes()));
        match current.prev() {
            Some(prev) => current = prev,
            None => return,
        }
    };
    if hashes.is_empty() {
        return;
    }
    let fork_height = best_height - hashes.len() as i32;
    hashes.reverse();
    let mut state = download.lock().unwrap();
    if !state.queue.is_empty() {
        return;
    }
    let queued: VecDeque<BlockHash> = hashes
        .into_iter()
        .filter(|hash| !state.received.contains(hash) && !state.in_flight.contains(hash))
        .collect();
    if queued.is_empty() {
        return;
    }
    info!(
        target: Category::NET,
        "Built download queue with {} blocks (heights {} to {}) forking at {}",
        queued.len(),
        fork_height + 1,
        best_height,
        fork_point
    );
    state.queue = queued;
}

fn create_getheaders_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    })
}

fn create_getblocks_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetBlocks(GetBlocksMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::all_zeros(),
    })
}

fn create_getdata_message(block_hashes: &[bitcoin::BlockHash]) -> NetworkMessage {
    let inventory: Vec<Inventory> = block_hashes
        .iter()
        .map(|hash| Inventory::WitnessBlock(*hash))
        .collect();

    NetworkMessage::GetData(inventory)
}

pub fn process_message(
    state_machine: PeerStateMachine,
    event: NetworkMessage,
    source: &AddrV2,
    node_state: &NodeState,
) -> (PeerStateMachine, Vec<NetworkMessage>) {
    // Always process the ping first as a special case.
    if let NetworkMessage::Ping(nonce) = event {
        info!(target: Category::NET, "Received ping, responding pong.");
        return (state_machine, vec![NetworkMessage::Pong(nonce)]);
    }

    if let NetworkMessage::AddrV2(payload) = event {
        info!(target: Category::NET, "Received {} net addresses", payload.len());
        // If the address manager has a full queue these net addresses should be dropped.
        let _ = node_state.addr_tx.send((source.clone(), payload));
        return (state_machine, vec![]);
    }

    match state_machine {
        PeerStateMachine::AwaitingHeaders => match event {
            NetworkMessage::Headers(headers) => {
                let msg_len = headers.len();
                for header in headers.into_iter() {
                    let result = node_state.chainman.process_block_header(&header.convert());
                    match result {
                        Ok(ProcessBlockHeaderResult::Valid) => {
                            debug!(target: Category::KERNEL, "Processed header: {}", header.time);
                            continue;
                        }
                        _ => {
                            warn!(target: Category::KERNEL, "Rejected header {}", header.block_hash());
                            break;
                        }
                    }
                }

                if msg_len != 2000 {
                    populate_download_queue(&node_state.chainman, &node_state.download);
                    let batch = node_state
                        .download
                        .lock()
                        .unwrap()
                        .pop_batch(DOWNLOAD_BATCH_SIZE);
                    if !batch.is_empty() {
                        return (
                            PeerStateMachine::AwaitingBlock(AwaitingBlock {
                                peer_inventory: batch.iter().cloned().collect(),
                            }),
                            vec![create_getdata_message(&batch)],
                        );
                    }
                    let locators = build_block_locators(node_state.chainman.active_chain().tip());
                    return (
                        PeerStateMachine::AwaitingInv,
                        vec![create_getblocks_message(locators)],
                    );
                }

                let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
                (
                    PeerStateMachine::AwaitingHeaders,
                    vec![create_getheaders_message(locators)],
                )
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingHeaders, vec![])
            }
        },
        PeerStateMachine::AwaitingInv => match event {
            NetworkMessage::Headers(headers) => {
                let mut announced = Vec::with_capacity(headers.len());
                for header in headers {
                    let block_hash = header.block_hash();
                    let valid = matches!(
                        node_state.chainman.process_block_header(&header.convert()),
                        Ok(ProcessBlockHeaderResult::Valid)
                    );
                    if !valid {
                        warn!(target: Category::KERNEL, "Rejected announced header {}", block_hash);
                        break;
                    }
                    announced.push(block_hash);
                }

                if announced.is_empty() {
                    let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
                    return (
                        PeerStateMachine::AwaitingHeaders,
                        vec![create_getheaders_message(locators)],
                    );
                }

                let claimed = node_state.download.lock().unwrap().claim(announced);
                if claimed.is_empty() {
                    return (PeerStateMachine::AwaitingInv, vec![]);
                }
                debug!(target: Category::NET, "Requesting {} announced blocks", claimed.len());
                (
                    PeerStateMachine::AwaitingBlock(AwaitingBlock {
                        peer_inventory: claimed.iter().copied().collect(),
                    }),
                    vec![create_getdata_message(&claimed)],
                )
            }
            NetworkMessage::Inv(inventory) => {
                debug!(target: Category::NET, "Received inventory with {} items", inventory.len());
                let block_hashes: Vec<bitcoin::BlockHash> = inventory
                    .iter()
                    .filter_map(|inv| match inv {
                        Inventory::Block(hash) => Some(*hash),
                        _ => None,
                    })
                    .collect();

                if !block_hashes.is_empty() {
                    // The queue walks block tree entries, which need these
                    // headers first.
                    let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
                    (
                        PeerStateMachine::AwaitingHeaders,
                        vec![create_getheaders_message(locators)],
                    )
                } else {
                    (PeerStateMachine::AwaitingInv, vec![])
                }
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingInv, vec![])
            }
        },
        PeerStateMachine::AwaitingBlock(mut block_state) => match event {
            NetworkMessage::Block(block) => {
                let block_hash = block.block_hash();
                block_state.peer_inventory.remove(&block_hash);
                // Another peer may have delivered it already.
                if node_state.download.lock().unwrap().receive(block_hash) {
                    // Fails only after the processing thread stops.
                    let _ = node_state.block_tx.send(block.convert());
                }

                if block_state.peer_inventory.is_empty() {
                    let batch = node_state
                        .download
                        .lock()
                        .unwrap()
                        .pop_batch(DOWNLOAD_BATCH_SIZE);
                    if !batch.is_empty() {
                        (
                            PeerStateMachine::AwaitingBlock(AwaitingBlock {
                                peer_inventory: batch.iter().cloned().collect(),
                            }),
                            vec![create_getdata_message(&batch)],
                        )
                    } else {
                        let locators =
                            build_block_locators(node_state.chainman.active_chain().tip());
                        (
                            PeerStateMachine::AwaitingInv,
                            vec![create_getblocks_message(locators)],
                        )
                    }
                } else {
                    (PeerStateMachine::AwaitingBlock(block_state), vec![])
                }
            }
            message => {
                debug!(target: Category::NET, "Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingBlock(block_state), vec![])
            }
        },
    }
}

fn stalled(state: &PeerStateMachine, last_progress: Instant) -> bool {
    !matches!(state, PeerStateMachine::AwaitingInv) && last_progress.elapsed() > PEER_STALL_TIMEOUT
}

fn delivers_requested_block(state: &PeerStateMachine, msg: &NetworkMessage) -> bool {
    matches!(
        (state, msg),
        (PeerStateMachine::AwaitingBlock(awaiting), NetworkMessage::Block(block))
            if awaiting.peer_inventory.contains(&block.block_hash())
    )
}

pub struct BitcoinPeer {
    dest: Destination,
    writer: Arc<ConnectionWriter>,
    reader: ConnectionReader,
    state_machine: PeerStateMachine,
    last_progress: Instant,
}

impl fmt::Display for BitcoinPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dest)
    }
}

impl BitcoinPeer {
    pub fn new(
        destination: Destination,
        proxy: Option<Socks5Proxy>,
        network: Network,
        node_state: &NodeState,
    ) -> Result<Self, p2p::net::Error> {
        let height = node_state.chainman.active_chain().height();
        let conf = ConnectionConfig::new()
            .change_network(network)
            .our_height(height)
            .request_addr()
            .set_service_requirement(ServiceFlags::NETWORK)
            .offer_services(ServiceFlags::WITNESS)
            .user_agent("/kernel-node:0.1.0/".into());
        let (writer, reader) = manager::connect(conf, &destination, proxy.as_ref(), READ_TIMEOUT)?;

        let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
        debug!(target: Category::NET, "Sending headers message...");
        writer.send_message(create_getheaders_message(locators))?;
        let peer = BitcoinPeer {
            dest: destination,
            writer: Arc::new(writer),
            reader,
            state_machine: PeerStateMachine::AwaitingHeaders,
            last_progress: Instant::now(),
        };
        Ok(peer)
    }

    pub fn writer(&self) -> Arc<ConnectionWriter> {
        Arc::clone(&self.writer)
    }

    pub fn is_stalled(&self) -> bool {
        stalled(&self.state_machine, self.last_progress)
    }

    pub fn release_in_flight(&self, download: &Mutex<DownloadState>) {
        if let PeerStateMachine::AwaitingBlock(state) = &self.state_machine {
            download
                .lock()
                .unwrap()
                .requeue_unreceived(&state.peer_inventory);
        }
    }

    fn receive_message(&mut self) -> Result<NetworkMessage, p2p::net::Error> {
        Ok(self
            .reader
            .read_message()?
            .expect("v1 only supported currently"))
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &NodeState,
    ) -> Result<(), p2p::net::Error> {
        let msg = self.receive_message()?;
        if let NetworkMessage::Block(block) = &msg {
            debug!(target: Category::NET, "Received block {} from {}", block.block_hash(), self);
        }
        let delivered = delivers_requested_block(&self.state_machine, &msg);
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) =
            process_message(old_state, msg, &self.dest.addr, node_state);
        self.state_machine = peer_state_machine;
        let requested = messages.iter().any(|message| {
            matches!(
                message,
                NetworkMessage::GetHeaders(_) | NetworkMessage::GetData(_)
            )
        });
        if delivered || requested {
            self.last_progress = Instant::now();
        }
        for message in messages.drain(..) {
            if let NetworkMessage::GetData(inventory) = &message {
                for item in inventory {
                    if let Inventory::WitnessBlock(hash) = item {
                        debug!(target: Category::NET, "Requesting block {} from {}", hash, self);
                    }
                }
            }
            self.writer.send_message(message)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn download(queue: &[BlockHash], in_flight: &[BlockHash]) -> DownloadState {
        DownloadState {
            queue: queue.iter().copied().collect(),
            in_flight: in_flight.iter().copied().collect(),
            ..Default::default()
        }
    }

    fn block_chain(len: usize) -> Vec<bitcoin::Block> {
        let mut blocks = Vec::with_capacity(len);
        let mut prev = bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
        for i in 0..len {
            let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            block.header.prev_blockhash = prev;
            block.header.nonce = i as u32;
            prev = block.block_hash();
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn pop_batch_returns_requested_count() {
        let mut d = download(&[hash(1), hash(2), hash(3), hash(4)], &[]);
        assert_eq!(d.pop_batch(2), vec![hash(1), hash(2)]);
        assert_eq!(d.queue.len(), 2);
    }

    #[test]
    fn receive_reports_in_flight_membership() {
        let mut d = download(&[hash(1)], &[]);
        assert!(!d.receive(hash(1)));
        d.pop_batch(1);
        assert!(d.receive(hash(1)));
        assert!(!d.receive(hash(1)));
        assert!(!d.receive(hash(2)));
        assert_eq!(d.received, HashSet::from([hash(1)]));
    }

    #[test]
    fn pop_batch_marks_in_flight() {
        let mut d = download(&[hash(1), hash(2)], &[]);
        d.pop_batch(2);
        assert!(d.in_flight.contains(&hash(1)));
        assert!(d.in_flight.contains(&hash(2)));
    }

    #[test]
    fn pop_batch_skips_already_in_flight() {
        let mut d = download(&[hash(1), hash(2), hash(3)], &[hash(2)]);
        assert_eq!(d.pop_batch(3), vec![hash(1), hash(3)]);
    }

    #[test]
    fn pop_batch_returns_partial_when_queue_short() {
        let mut d = download(&[hash(1)], &[]);
        assert_eq!(d.pop_batch(16), vec![hash(1)]);
        assert!(d.queue.is_empty());
    }

    #[test]
    fn pop_batch_returns_empty_when_queue_empty() {
        let mut d = download(&[], &[]);
        assert!(d.pop_batch(16).is_empty());
    }

    #[test]
    fn pop_batch_returns_empty_when_all_in_flight() {
        let mut d = download(&[hash(1), hash(2)], &[hash(1), hash(2)]);
        assert!(d.pop_batch(16).is_empty());
        assert!(d.queue.is_empty());
    }

    #[test]
    fn pop_batch_multiple_calls_drain_queue() {
        let mut d = download(&[hash(1), hash(2), hash(3), hash(4)], &[]);
        assert_eq!(d.pop_batch(2), vec![hash(1), hash(2)]);
        assert_eq!(d.pop_batch(2), vec![hash(3), hash(4)]);
        assert!(d.pop_batch(2).is_empty());
    }

    #[test]
    fn pop_batch_zero_batch_size() {
        let mut d = download(&[hash(1), hash(2)], &[]);
        assert!(d.pop_batch(0).is_empty());
        assert_eq!(d.queue.len(), 2);
    }

    #[test]
    fn pop_batch_preserves_fifo_order() {
        let mut d = download(&[hash(1), hash(2), hash(3), hash(4), hash(5)], &[]);
        assert_eq!(
            d.pop_batch(5),
            vec![hash(1), hash(2), hash(3), hash(4), hash(5)]
        );
    }

    fn long_ago() -> Instant {
        Instant::now() - PEER_STALL_TIMEOUT - Duration::from_secs(1)
    }

    #[test]
    fn stalled_when_awaiting_headers_past_timeout() {
        assert!(stalled(&PeerStateMachine::AwaitingHeaders, long_ago()));
    }

    #[test]
    fn stalled_when_awaiting_block_past_timeout() {
        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::new(),
        });
        assert!(stalled(&state, long_ago()));
    }

    #[test]
    fn not_stalled_when_awaiting_inv() {
        assert!(!stalled(&PeerStateMachine::AwaitingInv, long_ago()));
    }

    #[test]
    fn not_stalled_with_recent_progress() {
        assert!(!stalled(&PeerStateMachine::AwaitingHeaders, Instant::now()));
    }

    #[test]
    fn delivered_when_block_was_requested() {
        let blocks = block_chain(1);
        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::from([blocks[0].block_hash()]),
        });
        assert!(delivers_requested_block(
            &state,
            &NetworkMessage::Block(blocks[0].clone())
        ));
    }

    #[test]
    fn not_delivered_when_block_was_not_requested() {
        let blocks = block_chain(2);
        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::from([blocks[0].block_hash()]),
        });
        assert!(!delivers_requested_block(
            &state,
            &NetworkMessage::Block(blocks[1].clone())
        ));
    }

    #[test]
    fn requeue_unreceived_restores_queue_and_clears_in_flight() {
        let mut d = download(&[hash(5), hash(6)], &[hash(1), hash(2), hash(3)]);
        d.requeue_unreceived(&HashSet::from([hash(1), hash(2)]));
        assert_eq!(d.queue.len(), 4);
        assert!(d.queue.contains(&hash(1)));
        assert!(d.queue.contains(&hash(2)));
        assert!(!d.in_flight.contains(&hash(1)));
        assert!(!d.in_flight.contains(&hash(2)));
        assert!(d.in_flight.contains(&hash(3)));
    }

    #[test]
    fn requeue_unreceived_blocks_can_be_repopped() {
        let mut d = download(&[hash(5)], &[hash(1)]);
        d.requeue_unreceived(&HashSet::from([hash(1)]));
        assert_eq!(d.pop_batch(16), vec![hash(1), hash(5)]);
    }

    #[test]
    fn requeue_unreceived_noop_on_empty() {
        let mut d = download(&[hash(1)], &[hash(2)]);
        d.requeue_unreceived(&HashSet::new());
        assert_eq!(d.queue.len(), 1);
        assert!(d.in_flight.contains(&hash(2)));
    }

    #[test]
    fn forget_connected_stops_at_first_hash_not_received() {
        let mut d = DownloadState {
            received: HashSet::from([hash(1), hash(3), hash(4)]),
            ..Default::default()
        };
        d.forget_connected([hash(4), hash(3), hash(2), hash(1)]);
        assert_eq!(d.received, HashSet::from([hash(1)]));
    }
}
