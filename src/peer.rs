use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bitcoin::{BlockHash, Network};
use bitcoinkernel::{
    core::BlockHashExt, prelude::BlockValidationStateExt, ChainstateManager, Context,
    ProcessBlockHeaderResult, ValidationMode,
};
use log::{debug, info, warn};
use p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, ConnectionReader, ConnectionWriter, TimeoutParams},
    p2p_message_types::{
        message::{AddrV2Payload, InventoryPayload, NetworkMessage},
        message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory},
        message_network::UserAgent,
        Address, ProtocolVersion, ServiceFlags,
    },
};

use crate::kernel_util::{bitcoin_block_to_kernel_block, bitcoin_header_to_kernel_header};

const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::INVALID_CB_NO_BAN_VERSION;

/// Number of blocks each peer requests per batch from the download queue.
const DOWNLOAD_BATCH_SIZE: usize = 16;

/// If a peer stays in an active IBD state (AwaitingHeaders or AwaitingBlock)
/// for this long without making progress, it is considered stalled and
/// disconnected. AwaitingInv is exempt: it is the rest state where waiting
/// is expected (steady-state post-IBD, or between batches when the queue
/// is temporarily exhausted).
const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Walk backwards from the header tip to the active chain tip, collecting
/// block hashes into the download queue. Only populates if the queue is empty.
fn populate_download_queue(chainman: &ChainstateManager, queue: &Mutex<VecDeque<BlockHash>>) {
    // Early-exit without holding the lock during the chain walk.
    // We re-check under the lock below before assigning.
    if !queue.lock().unwrap().is_empty() {
        return;
    }
    let active_height = chainman.active_chain().height();
    let best = match chainman.best_entry() {
        Some(entry) => entry,
        None => return,
    };
    let best_height = best.height();
    if best_height <= active_height {
        return;
    }
    let count = (best_height - active_height) as usize;
    let mut hashes = Vec::with_capacity(count);
    let mut current = best;
    while current.height() > active_height {
        let hash = BlockHash::from_byte_array(current.block_hash().to_bytes());
        hashes.push(hash);
        match current.prev() {
            Some(prev) => current = prev,
            None => break,
        }
    }
    hashes.reverse();
    // Acquire the lock only to assign. Re-check emptiness in case another
    // thread populated the queue while we were walking the chain.
    let mut q = queue.lock().unwrap();
    if !q.is_empty() {
        return;
    }
    info!(
        "Built download queue with {} blocks (heights {} to {})",
        hashes.len(),
        active_height + 1,
        best_height
    );
    *q = VecDeque::from(hashes);
}

/// Pop up to `batch_size` block hashes from the download queue and mark
/// them as in-flight. Always locks queue first, then in_flight.
fn pop_download_batch(
    queue: &Mutex<VecDeque<BlockHash>>,
    in_flight: &Mutex<HashSet<BlockHash>>,
    batch_size: usize,
) -> Vec<BlockHash> {
    let mut q = queue.lock().unwrap();
    let mut in_flight = in_flight.lock().unwrap();
    let mut batch = Vec::with_capacity(batch_size);
    while batch.len() < batch_size {
        match q.pop_front() {
            Some(hash) => {
                if !in_flight.contains(&hash) {
                    in_flight.insert(hash);
                    batch.push(hash);
                }
            }
            None => break,
        }
    }
    batch
}

#[derive(Clone)]
pub struct TipState {
    pub block_hash: bitcoin::BlockHash,
}

impl Default for TipState {
    fn default() -> Self {
        Self {
            block_hash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
        }
    }
}

pub struct NodeState {
    pub addr_tx: mpsc::Sender<AddrV2Payload>,
    pub block_tx: mpsc::SyncSender<bitcoinkernel::Block>,
    pub tip_state: Arc<Mutex<TipState>>,
    pub context: Arc<Context>,
    pub chainman: Arc<ChainstateManager>,
    /// Tracks block hashes currently being downloaded by any peer.
    /// Peers claim hashes when requesting blocks and release them
    /// on receipt or disconnect.
    pub in_flight_blocks: Mutex<HashSet<BlockHash>>,
    /// Pre-built queue of block hashes to download, populated after
    /// header sync by walking backwards from the header tip.
    pub download_queue: Mutex<VecDeque<BlockHash>>,
    /// Set to true once the first peer finishes header sync and
    /// populates the download queue. Late-arriving peers skip
    /// headers and go straight to block downloading.
    pub headers_synced: AtomicBool,
}

impl NodeState {
    pub fn set_tip_state(&self, block_hash: bitcoin::BlockHash) {
        let mut state = self.tip_state.lock().unwrap();
        state.block_hash = block_hash;
    }

    pub fn get_tip_state(&self) -> TipState {
        let state = self.tip_state.lock().unwrap();
        state.clone()
    }
}

/// State Machine for setting up a connection and getting blocks from a peer
///
/// ```text
///          [*]
///           │
///    AwaitingHeaders
///      /          \
///  (queue)     (no queue)
///    /              \
/// AwaitingBlock  AwaitingInv
///    │  ▲           ▲ |
///    │  │     Block | | Inv
///    └──┘           | ▼
///  (next batch)  AwaitingBlock
///    │               │ ▲
///    │ (queue empty)  └─┘
///    └──> AwaitingInv
/// ```
#[derive(Default)]
pub enum PeerStateMachine {
    #[default]
    AwaitingHeaders,
    AwaitingInv,
    AwaitingBlock(AwaitingBlock),
}

pub struct AwaitingBlock {
    pub peer_inventory: HashSet<bitcoin::BlockHash>,
    pub block_buffer: HashMap<bitcoin::BlockHash /*prev */, bitcoinkernel::Block>,
    /// Hash of the last block this peer has sent to the block processing
    /// channel (block_tx). Updated eagerly on each send so the buffer can
    /// drain in chain order without waiting for kernel validation to advance
    /// the global tip.
    pub local_tip: bitcoin::BlockHash,
}

/// Build a logarithmic block locator from the active chain.
///
/// Returns hashes at heights: tip, tip-1, tip-2, tip-3, ..., tip-10,
/// then doubling the step (tip-12, tip-16, tip-24, ...), always ending
/// with the genesis block. This helps the remote peer find the fork
/// point even after a reorg.
fn build_block_locator(chainman: &ChainstateManager) -> Vec<BlockHash> {
    let chain = chainman.active_chain();
    let height = chain.height();
    if height < 0 {
        return vec![];
    }
    let mut locator = Vec::new();
    let mut index = height as usize;
    let mut step: usize = 1;
    loop {
        if let Some(entry) = chain.at_height(index) {
            let hash = BlockHash::from_byte_array(entry.block_hash().to_bytes());
            locator.push(hash);
        }
        if index == 0 {
            break;
        }
        if locator.len() > 10 {
            step *= 2;
        }
        index = index.saturating_sub(step);
    }
    locator
}

fn create_getheaders_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    })
}

fn create_getblocks_message(locator_hashes: Vec<bitcoin::BlockHash>) -> NetworkMessage {
    NetworkMessage::GetBlocks(GetBlocksMessage {
        version: PROTOCOL_VERSION,
        locator_hashes,
        stop_hash: bitcoin::BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    })
}

fn create_getdata_message(block_hashes: &[bitcoin::BlockHash]) -> NetworkMessage {
    let inventory: Vec<Inventory> = block_hashes
        .iter()
        .map(|hash| Inventory::WitnessBlock(*hash))
        .collect();

    NetworkMessage::GetData(InventoryPayload(inventory))
}

pub fn process_message(
    state_machine: PeerStateMachine,
    event: NetworkMessage,
    node_state: &NodeState,
) -> (PeerStateMachine, Vec<NetworkMessage>) {
    // Always process the ping first as a special case.
    if let NetworkMessage::Ping(nonce) = event {
        debug!("Received ping, responding pong.");
        return (state_machine, vec![NetworkMessage::Pong(nonce)]);
    }

    if let NetworkMessage::AddrV2(payload) = event {
        info!("Received {} net addresses", payload.0.len());
        // If the address manager has a full queue these net addresses should be dropped.
        let _ = node_state.addr_tx.send(payload);
        return (state_machine, vec![]);
    }

    match state_machine {
        PeerStateMachine::AwaitingHeaders => match event {
            NetworkMessage::Headers(headers) => {
                for header in &headers.0 {
                    let result = node_state
                        .chainman
                        .process_block_header(&bitcoin_header_to_kernel_header(&header));
                    match result {
                        ProcessBlockHeaderResult::Success(state)
                            if state.mode() == ValidationMode::Valid =>
                        {
                            debug!("Processed header: {}", header.time.to_u32());
                            continue;
                        }
                        _ => {
                            warn!("Rejected header {}", header.block_hash());
                            break;
                        }
                    }
                }

                if headers.0.len() != 2000 {
                    populate_download_queue(&node_state.chainman, &node_state.download_queue);
                    node_state.headers_synced.store(true, Ordering::SeqCst);
                    let batch = pop_download_batch(
                        &node_state.download_queue,
                        &node_state.in_flight_blocks,
                        DOWNLOAD_BATCH_SIZE,
                    );
                    if !batch.is_empty() {
                        return (
                            PeerStateMachine::AwaitingBlock(AwaitingBlock {
                                peer_inventory: batch.iter().cloned().collect(),
                                block_buffer: HashMap::new(),
                                local_tip: node_state.get_tip_state().block_hash,
                            }),
                            vec![create_getdata_message(&batch)],
                        );
                    }
                    let locator = build_block_locator(&node_state.chainman);
                    return (
                        PeerStateMachine::AwaitingInv,
                        vec![create_getblocks_message(locator)],
                    );
                }

                let locator = build_block_locator(&node_state.chainman);
                (
                    PeerStateMachine::AwaitingHeaders,
                    vec![create_getheaders_message(locator)],
                )
            }
            message => {
                debug!("Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingHeaders, vec![])
            }
        },
        PeerStateMachine::AwaitingInv => match event {
            NetworkMessage::Inv(inventory) => {
                debug!("Received inventory with {} items", inventory.0.len());
                let block_hashes: Vec<bitcoin::BlockHash> = inventory
                    .0
                    .iter()
                    .filter_map(|inv| match inv {
                        Inventory::Block(hash) => Some(*hash),
                        _ => None,
                    })
                    .collect();

                if !block_hashes.is_empty() {
                    let mut in_flight = node_state.in_flight_blocks.lock().unwrap();
                    let claimed: Vec<bitcoin::BlockHash> = block_hashes
                        .into_iter()
                        .filter(|h| !in_flight.contains(h))
                        .collect();
                    for h in &claimed {
                        in_flight.insert(*h);
                    }
                    drop(in_flight);

                    if !claimed.is_empty() {
                        debug!("Requesting {} blocks", claimed.len());
                        (
                            PeerStateMachine::AwaitingBlock(AwaitingBlock {
                                peer_inventory: claimed.iter().cloned().collect(),
                                block_buffer: HashMap::new(),
                                local_tip: node_state.get_tip_state().block_hash,
                            }),
                            vec![create_getdata_message(&claimed)],
                        )
                    } else {
                        let locator = build_block_locator(&node_state.chainman);
                        (
                            PeerStateMachine::AwaitingInv,
                            vec![create_getblocks_message(locator)],
                        )
                    }
                } else {
                    (PeerStateMachine::AwaitingInv, vec![])
                }
            }
            message => {
                debug!("Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingInv, vec![])
            }
        },
        PeerStateMachine::AwaitingBlock(mut block_state) => match event {
            NetworkMessage::Block(block) => {
                let block = block.assume_checked(None);
                let block_hash = block.block_hash();
                let prev_blockhash = block.header().prev_blockhash;
                block_state.peer_inventory.remove(&block_hash);
                node_state
                    .in_flight_blocks
                    .lock()
                    .unwrap()
                    .remove(&block_hash);
                block_state
                    .block_buffer
                    .insert(prev_blockhash, bitcoin_block_to_kernel_block(&block));

                while let Some(next_block) = block_state.block_buffer.remove(&block_state.local_tip) {
                    let next_hash = BlockHash::from_byte_array(next_block.hash().into());
                    block_state.local_tip = next_hash;
                    if let Err(err) = node_state.block_tx.send(next_block) {
                        debug!("Encountered error on block send: {}", err);
                        return (PeerStateMachine::AwaitingBlock(block_state), vec![]);
                    }
                }

                // If all expected blocks were received, request the next batch.
                // With local_tip draining, the buffer must be empty at this point.
                if block_state.peer_inventory.is_empty() {
                    debug_assert!(
                        block_state.block_buffer.is_empty(),
                        "block_buffer should be fully drained when peer_inventory empties"
                    );
                    let batch = pop_download_batch(
                        &node_state.download_queue,
                        &node_state.in_flight_blocks,
                        DOWNLOAD_BATCH_SIZE,
                    );
                    if !batch.is_empty() {
                        (
                            PeerStateMachine::AwaitingBlock(AwaitingBlock {
                                peer_inventory: batch.iter().cloned().collect(),
                                block_buffer: HashMap::new(),
                                local_tip: block_state.local_tip,
                            }),
                            vec![create_getdata_message(&batch)],
                        )
                    } else {
                        let locator = build_block_locator(&node_state.chainman);
                        (
                            PeerStateMachine::AwaitingInv,
                            vec![create_getblocks_message(locator)],
                        )
                    }
                } else {
                    (PeerStateMachine::AwaitingBlock(block_state), vec![])
                }
            }
            message => {
                debug!("Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingBlock(block_state), vec![])
            }
        },
    }
}

/// Remove `inventory` hashes from the in-flight set and push them to the
/// front of the download queue so another peer can re-request them.
/// No-ops if `inventory` is empty. Always locks queue first, then in_flight.
fn requeue_unreceived(
    inventory: &HashSet<BlockHash>,
    queue: &Mutex<VecDeque<BlockHash>>,
    in_flight: &Mutex<HashSet<BlockHash>>,
) {
    if inventory.is_empty() {
        return;
    }
    let mut q = queue.lock().unwrap();
    let mut set = in_flight.lock().unwrap();
    for hash in inventory {
        set.remove(hash);
        q.push_front(*hash);
    }
    debug!("Re-enqueued {} unreceived blocks", inventory.len());
}

/// Re-insert blocks from `buffer` into the download queue so another peer
/// can re-download them. These are blocks that arrived out of order and
/// could not be forwarded because the chain was not contiguous from
/// `local_tip`. They were already removed from `in_flight_blocks` on
/// arrival, so only the queue needs updating.
fn requeue_buffered(
    buffer: &HashMap<BlockHash, bitcoinkernel::Block>,
    queue: &Mutex<VecDeque<BlockHash>>,
) {
    if buffer.is_empty() {
        return;
    }
    let mut q = queue.lock().unwrap();
    for block in buffer.values() {
        let hash = BlockHash::from_byte_array(block.hash().into());
        q.push_front(hash);
    }
    debug!("Re-enqueued {} buffered blocks on peer disconnect", buffer.len());
}

pub struct BitcoinPeer {
    addr: Address,
    writer: Arc<ConnectionWriter>,
    reader: ConnectionReader,
    state_machine: PeerStateMachine,
    /// Tracks when this peer last made progress (received a block or
    /// changed state). Used to detect stalled peers.
    last_progress: Instant,
}

impl fmt::Display for BitcoinPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.addr)
    }
}

impl BitcoinPeer {
    pub fn new(
        socket_addr: SocketAddr,
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
            .user_agent(UserAgent::from_nonstandard("kernel-node"));
        let (writer, reader, _) = conf.open_connection(socket_addr, TimeoutParams::new())?;

        let addr = Address::new(&socket_addr, ServiceFlags::WITNESS);
        info!("Connected to {:?}", addr);

        let state_machine;
        if node_state.headers_synced.load(Ordering::SeqCst) {
            let batch = pop_download_batch(
                &node_state.download_queue,
                &node_state.in_flight_blocks,
                DOWNLOAD_BATCH_SIZE,
            );
            if !batch.is_empty() {
                debug!("Headers already synced, starting block download.");
                let getdata = create_getdata_message(&batch);
                writer.send_message(getdata)?;
                state_machine = PeerStateMachine::AwaitingBlock(AwaitingBlock {
                    peer_inventory: batch.iter().cloned().collect(),
                    block_buffer: HashMap::new(),
                    local_tip: node_state.get_tip_state().block_hash,
                });
            } else {
                debug!("Headers synced but queue empty, falling back to inv.");
                let locator = build_block_locator(&node_state.chainman);
                writer.send_message(create_getblocks_message(locator))?;
                state_machine = PeerStateMachine::AwaitingInv;
            }
        } else {
            let locator = build_block_locator(&node_state.chainman);
            let getheaders = create_getheaders_message(locator);
            debug!("Sending getheaders message...");
            writer.send_message(getheaders)?;
            state_machine = PeerStateMachine::AwaitingHeaders;
        }

        let peer = BitcoinPeer {
            addr,
            writer: Arc::new(writer),
            reader,
            state_machine,
            last_progress: Instant::now(),
        };
        Ok(peer)
    }

    pub fn writer(&self) -> Arc<ConnectionWriter> {
        Arc::clone(&self.writer)
    }

    fn receive_message(&mut self) -> Result<NetworkMessage, p2p::net::Error> {
        Ok(self
            .reader
            .read_message()?
            .expect("v1 only supported currently"))
    }

    /// Release any block hashes this peer claimed but never received, and
    /// re-enqueue any blocks that arrived out of order and are still in the
    /// buffer. Pushes all of them to the front of the download queue so other
    /// peers can pick them up.
    pub fn release_in_flight(
        &self,
        queue: &Mutex<VecDeque<BlockHash>>,
        in_flight: &Mutex<HashSet<BlockHash>>,
    ) {
        if let PeerStateMachine::AwaitingBlock(ref state) = self.state_machine {
            requeue_unreceived(&state.peer_inventory, queue, in_flight);
            requeue_buffered(&state.block_buffer, queue);
        }
    }

    /// Returns true if this peer is in an active IBD state (AwaitingHeaders
    /// or AwaitingBlock) and has not made progress within PEER_STALL_TIMEOUT.
    /// Progress resets on: block received, headers batch received, or entering
    /// AwaitingBlock (i.e. sending a getdata request).
    /// AwaitingInv never stalls: it is the expected rest state.
    pub fn is_stalled(&self) -> bool {
        !matches!(self.state_machine, PeerStateMachine::AwaitingInv)
            && self.last_progress.elapsed() > PEER_STALL_TIMEOUT
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &NodeState,
    ) -> Result<(), p2p::net::Error> {
        let msg = self.receive_message()?;
        let is_block = matches!(msg, NetworkMessage::Block(_));
        let is_headers = matches!(msg, NetworkMessage::Headers(_));
        let was_awaiting_block =
            matches!(self.state_machine, PeerStateMachine::AwaitingBlock(_));
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) = process_message(old_state, msg, node_state);
        self.state_machine = peer_state_machine;

        let now_awaiting_block =
            matches!(self.state_machine, PeerStateMachine::AwaitingBlock(_));
        if is_block || is_headers || (now_awaiting_block && !was_awaiting_block) {
            self.last_progress = Instant::now();
        }

        for message in messages.drain(..) {
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
    #[test]
    fn pop_download_batch_returns_requested_count() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2), hash(3), hash(4)]));
        let in_flight = Mutex::new(HashSet::new());
        let batch = pop_download_batch(&queue, &in_flight, 2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], hash(1));
        assert_eq!(batch[1], hash(2));
        assert_eq!(queue.lock().unwrap().len(), 2);
    }

    #[test]
    fn pop_download_batch_marks_in_flight() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2)]));
        let in_flight = Mutex::new(HashSet::new());
        pop_download_batch(&queue, &in_flight, 2);
        let set = in_flight.lock().unwrap();
        assert!(set.contains(&hash(1)));
        assert!(set.contains(&hash(2)));
    }

    #[test]
    fn pop_download_batch_skips_already_in_flight() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2), hash(3)]));
        let in_flight = Mutex::new(HashSet::from([hash(2)]));
        let batch = pop_download_batch(&queue, &in_flight, 3);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], hash(1));
        assert_eq!(batch[1], hash(3));
    }

    #[test]
    fn pop_download_batch_returns_partial_when_queue_short() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1)]));
        let in_flight = Mutex::new(HashSet::new());
        let batch = pop_download_batch(&queue, &in_flight, 16);
        assert_eq!(batch.len(), 1);
        assert!(queue.lock().unwrap().is_empty());
    }

    #[test]
    fn pop_download_batch_returns_empty_when_queue_empty() {
        let queue = Mutex::new(VecDeque::new());
        let in_flight = Mutex::new(HashSet::new());
        let batch = pop_download_batch(&queue, &in_flight, 16);
        assert!(batch.is_empty());
    }

    #[test]
    fn pop_download_batch_returns_empty_when_all_in_flight() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2)]));
        let in_flight = Mutex::new(HashSet::from([hash(1), hash(2)]));
        let batch = pop_download_batch(&queue, &in_flight, 16);
        assert!(batch.is_empty());
        assert!(queue.lock().unwrap().is_empty());
    }

    #[test]
    fn pop_download_batch_multiple_calls_drain_queue() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2), hash(3), hash(4)]));
        let in_flight = Mutex::new(HashSet::new());
        let batch1 = pop_download_batch(&queue, &in_flight, 2);
        let batch2 = pop_download_batch(&queue, &in_flight, 2);
        let batch3 = pop_download_batch(&queue, &in_flight, 2);
        assert_eq!(batch1, vec![hash(1), hash(2)]);
        assert_eq!(batch2, vec![hash(3), hash(4)]);
        assert!(batch3.is_empty());
    }
    #[test]
    fn tip_state_default_is_genesis() {
        let state = TipState::default();
        assert_eq!(state.block_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
    }
    #[test]
    fn peer_state_machine_default_is_awaiting_headers() {
        let state = PeerStateMachine::default();
        assert!(matches!(state, PeerStateMachine::AwaitingHeaders));
    }
    #[test]
    fn create_getdata_message_wraps_as_witness_block() {
        let hashes = vec![hash(1), hash(2)];
        let msg = create_getdata_message(&hashes);
        match msg {
            NetworkMessage::GetData(payload) => {
                assert_eq!(payload.0.len(), 2);
                assert!(matches!(payload.0[0], Inventory::WitnessBlock(_)));
            }
            _ => panic!("expected GetData message"),
        }
    }

    #[test]
    fn create_getheaders_uses_protocol_version() {
        let msg = create_getheaders_message(vec![hash(1), hash(2)]);
        match msg {
            NetworkMessage::GetHeaders(gh) => {
                assert_eq!(gh.version, PROTOCOL_VERSION);
                assert_eq!(gh.locator_hashes.len(), 2);
                assert_eq!(gh.locator_hashes[0], hash(1));
                assert_eq!(gh.locator_hashes[1], hash(2));
            }
            _ => panic!("expected GetHeaders message"),
        }
    }
    #[test]
    fn requeue_unreceived_restores_queue_and_clears_in_flight() {
        let queue = Mutex::new(VecDeque::from(vec![hash(5), hash(6)]));
        let in_flight = Mutex::new(HashSet::from([hash(1), hash(2), hash(3)]));
        let inventory = HashSet::from([hash(1), hash(2)]);

        requeue_unreceived(&inventory, &queue, &in_flight);

        let q = queue.lock().unwrap();
        assert_eq!(q.len(), 4);
        assert!(q.contains(&hash(1)));
        assert!(q.contains(&hash(2)));
        assert!(q.contains(&hash(5)));
        assert!(q.contains(&hash(6)));

        let set = in_flight.lock().unwrap();
        assert!(!set.contains(&hash(1)));
        assert!(!set.contains(&hash(2)));
        assert!(set.contains(&hash(3)));
    }

    #[test]
    fn requeue_unreceived_blocks_can_be_repopped() {
        let queue = Mutex::new(VecDeque::from(vec![hash(5)]));
        let in_flight = Mutex::new(HashSet::from([hash(1)]));
        let inventory = HashSet::from([hash(1)]);

        requeue_unreceived(&inventory, &queue, &in_flight);

        let batch = pop_download_batch(&queue, &in_flight, 16);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], hash(1));
        assert_eq!(batch[1], hash(5));
    }

    #[test]
    fn requeue_unreceived_noop_on_empty_inventory() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1)]));
        let in_flight = Mutex::new(HashSet::from([hash(2)]));

        requeue_unreceived(&HashSet::new(), &queue, &in_flight);

        assert_eq!(queue.lock().unwrap().len(), 1);
        assert!(in_flight.lock().unwrap().contains(&hash(2)));
    }

    #[test]
    fn requeue_buffered_restores_arrived_blocks_to_queue() {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.header().block_hash();
        let prev_hash = genesis.header().prev_blockhash;

        let kernel_block = bitcoin_block_to_kernel_block(&genesis);
        let mut buffer: HashMap<BlockHash, bitcoinkernel::Block> = HashMap::new();
        buffer.insert(prev_hash, kernel_block);

        let queue = Mutex::new(VecDeque::from(vec![hash(5)]));
        requeue_buffered(&buffer, &queue);

        let q = queue.lock().unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0], genesis_hash, "buffered block re-queued at front");
        assert_eq!(q[1], hash(5), "existing queue entry preserved");
    }

    #[test]
    fn requeue_buffered_noop_on_empty_buffer() {
        let buffer: HashMap<BlockHash, bitcoinkernel::Block> = HashMap::new();
        let queue = Mutex::new(VecDeque::from(vec![hash(1)]));
        requeue_buffered(&buffer, &queue);
        assert_eq!(queue.lock().unwrap().len(), 1);
    }

    #[test]
    fn create_getblocks_uses_protocol_version() {
        let msg = create_getblocks_message(vec![hash(1), hash(2)]);
        match msg {
            NetworkMessage::GetBlocks(gb) => {
                assert_eq!(gb.version, PROTOCOL_VERSION);
                assert_eq!(gb.locator_hashes.len(), 2);
                assert_eq!(gb.locator_hashes[0], hash(1));
                assert_eq!(gb.locator_hashes[1], hash(2));
            }
            _ => panic!("expected GetBlocks message"),
        }
    }
    #[test]
    fn create_getdata_message_all_items_are_witness_block() {
        let hashes = vec![hash(1), hash(2), hash(3)];
        let msg = create_getdata_message(&hashes);
        match msg {
            NetworkMessage::GetData(payload) => {
                for (i, inv) in payload.0.iter().enumerate() {
                    assert!(
                        matches!(inv, Inventory::WitnessBlock(_)),
                        "item {} should be WitnessBlock, got {:?}",
                        i,
                        inv
                    );
                }
            }
            _ => panic!("expected GetData message"),
        }
    }

    #[test]
    fn create_getdata_message_empty_input() {
        let msg = create_getdata_message(&[]);
        match msg {
            NetworkMessage::GetData(payload) => {
                assert!(payload.0.is_empty());
            }
            _ => panic!("expected GetData message"),
        }
    }

    #[test]
    fn create_getheaders_stop_hash_is_genesis() {
        let msg = create_getheaders_message(vec![hash(1)]);
        match msg {
            NetworkMessage::GetHeaders(gh) => {
                assert_eq!(gh.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
            }
            _ => panic!("expected GetHeaders message"),
        }
    }

    #[test]
    fn create_getblocks_stop_hash_is_genesis() {
        let msg = create_getblocks_message(vec![hash(1)]);
        match msg {
            NetworkMessage::GetBlocks(gb) => {
                assert_eq!(gb.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
            }
            _ => panic!("expected GetBlocks message"),
        }
    }
    #[test]
    fn pop_download_batch_zero_batch_size() {
        let queue = Mutex::new(VecDeque::from(vec![hash(1), hash(2)]));
        let in_flight = Mutex::new(HashSet::new());
        let batch = pop_download_batch(&queue, &in_flight, 0);
        assert!(batch.is_empty());
        assert_eq!(queue.lock().unwrap().len(), 2);
    }

    #[test]
    fn pop_download_batch_preserves_fifo_order() {
        let queue = Mutex::new(VecDeque::from(vec![
            hash(1),
            hash(2),
            hash(3),
            hash(4),
            hash(5),
        ]));
        let in_flight = Mutex::new(HashSet::new());
        let batch = pop_download_batch(&queue, &in_flight, 5);
        assert_eq!(batch, vec![hash(1), hash(2), hash(3), hash(4), hash(5)]);
    }
    #[test]
    fn tip_state_clone_is_independent() {
        let original = TipState {
            block_hash: hash(1),
        };
        let mut cloned = original.clone();
        cloned.block_hash = hash(2);
        assert_eq!(original.block_hash, hash(1));
        assert_eq!(cloned.block_hash, hash(2));
    }

    use bitcoinkernel::{ChainType, ChainstateManagerBuilder, ContextBuilder};
    use p2p::p2p_message_types::message::HeadersMessage;
    use tempfile::TempDir;

    /// Return the regtest genesis block as `Block<BlockUnchecked>`.
    ///
    /// `genesis_block()` returns `Block<BlockChecked>`, but `NetworkMessage::Block`
    /// wraps `Block<BlockUnchecked>`. A consensus encode/decode round-trip strips
    /// the type marker while preserving all fields.
    fn regtest_genesis_unchecked() -> bitcoin::Block {
        let checked = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let bytes = bitcoin::consensus::serialize(&checked);
        bitcoin::consensus::deserialize(&bytes).unwrap()
    }

    /// Create a regtest NodeState for testing.
    ///
    /// Returns `(TempDir, Arc<NodeState>, block_rx)`. The caller **must** bind
    /// `block_rx` (e.g. `let (_tmp, node_state, _rx) = setup_regtest();`) to
    /// keep the receiver alive. If it is dropped, `block_tx.send()` inside
    /// `process_message` will return `Err` and the state machine will exit
    /// AwaitingBlock early instead of transitioning to the next state.
    fn setup_regtest() -> (TempDir, Arc<NodeState>, mpsc::Receiver<bitcoinkernel::Block>) {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let data_dir = tmp.path().join("data");
        let blocks_dir = tmp.path().join("blocks");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&blocks_dir).unwrap();

        let context = Arc::new(
            ContextBuilder::new()
                .chain_type(ChainType::Regtest)
                .build()
                .expect("failed to build regtest context"),
        );

        let chainman = Arc::new(
            ChainstateManagerBuilder::new(
                &context,
                data_dir.to_str().unwrap(),
                blocks_dir.to_str().unwrap(),
            )
            .expect("failed to create chainstate manager builder")
            .build()
            .expect("failed to build chainstate manager"),
        );

        chainman.import_blocks().expect("failed to import blocks");

        let (block_tx, block_rx) = mpsc::sync_channel(32);
        let (addr_tx, _addr_rx) = mpsc::channel();
        let tip_hash =
            BlockHash::from_byte_array(chainman.active_chain().tip().block_hash().to_bytes());

        let node_state = Arc::new(NodeState {
            addr_tx,
            block_tx,
            tip_state: Arc::new(Mutex::new(TipState {
                block_hash: tip_hash,
            })),
            context,
            chainman,
            in_flight_blocks: Mutex::new(HashSet::new()),
            download_queue: Mutex::new(VecDeque::new()),
            headers_synced: AtomicBool::new(false),
        });

        (tmp, node_state, block_rx)
    }

    #[test]
    fn regtest_initial_chain_state() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let height = node_state.chainman.active_chain().height();
        assert_eq!(height, 0, "regtest should start at height 0");
        assert!(!node_state.headers_synced.load(Ordering::SeqCst));
        assert!(node_state.download_queue.lock().unwrap().is_empty());
        assert!(node_state.in_flight_blocks.lock().unwrap().is_empty());
    }

    #[test]
    fn regtest_process_ping_returns_pong() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let (state, messages) = process_message(
            PeerStateMachine::AwaitingHeaders,
            NetworkMessage::Ping(42),
            &node_state,
        );
        assert!(matches!(state, PeerStateMachine::AwaitingHeaders));
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], NetworkMessage::Pong(42)));
    }

    #[test]
    fn regtest_empty_headers_completes_sync() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let (state, messages) = process_message(
            PeerStateMachine::AwaitingHeaders,
            NetworkMessage::Headers(HeadersMessage(vec![])),
            &node_state,
        );
        assert!(node_state.headers_synced.load(Ordering::SeqCst));
        assert!(matches!(state, PeerStateMachine::AwaitingInv));
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], NetworkMessage::GetBlocks(_)));
    }

    #[test]
    fn regtest_headers_synced_flag_persists() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let _ = process_message(
            PeerStateMachine::AwaitingHeaders,
            NetworkMessage::Headers(HeadersMessage(vec![])),
            &node_state,
        );
        assert!(node_state.headers_synced.load(Ordering::SeqCst));
        let _ = process_message(
            PeerStateMachine::AwaitingHeaders,
            NetworkMessage::Headers(HeadersMessage(vec![])),
            &node_state,
        );
        assert!(node_state.headers_synced.load(Ordering::SeqCst));
    }

    #[test]
    fn regtest_process_block_header_genesis() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let kernel_header = bitcoin_header_to_kernel_header(genesis.header());
        let result = node_state.chainman.process_block_header(&kernel_header);
        assert!(matches!(result, ProcessBlockHeaderResult::Success(_)));
    }

    #[test]
    fn regtest_inv_deduplication() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let (state, _) = process_message(
            PeerStateMachine::AwaitingHeaders,
            NetworkMessage::Headers(HeadersMessage(vec![])),
            &node_state,
        );
        assert!(matches!(state, PeerStateMachine::AwaitingInv));

        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.header().block_hash();
        let inv = NetworkMessage::Inv(InventoryPayload(vec![Inventory::Block(genesis_hash)]));
        let (state, messages) = process_message(state, inv, &node_state);
        assert!(node_state
            .in_flight_blocks
            .lock()
            .unwrap()
            .contains(&genesis_hash));
        assert!(matches!(state, PeerStateMachine::AwaitingBlock(_)));
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], NetworkMessage::GetData(_)));

        let inv2 = NetworkMessage::Inv(InventoryPayload(vec![Inventory::Block(genesis_hash)]));
        let (state2, messages2) = process_message(PeerStateMachine::AwaitingInv, inv2, &node_state);
        assert!(matches!(state2, PeerStateMachine::AwaitingInv));
        assert_eq!(messages2.len(), 1);
        assert!(matches!(messages2[0], NetworkMessage::GetBlocks(_)));
    }

    #[test]
    fn local_tip_advances_on_block_receipt() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let genesis_checked = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis_checked.header().block_hash();
        let prev_hash = genesis_checked.header().prev_blockhash;
        let genesis = regtest_genesis_unchecked();

        // Two blocks expected: genesis + one placeholder (hash(99)).
        // Having two keeps peer_inventory non-empty after genesis arrives so
        // we stay in AwaitingBlock and can inspect local_tip directly.
        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::from([genesis_hash, hash(99)]),
            block_buffer: HashMap::new(),
            local_tip: prev_hash,
        });

        let (new_state, messages) = process_message(
            state,
            NetworkMessage::Block(genesis),
            &node_state,
        );

        assert!(messages.is_empty(), "no outbound messages while batch still incomplete");
        match new_state {
            PeerStateMachine::AwaitingBlock(ref ab) => {
                assert_eq!(
                    ab.local_tip, genesis_hash,
                    "local_tip must advance to the received block's hash"
                );
                assert_eq!(ab.peer_inventory.len(), 1);
                assert!(ab.peer_inventory.contains(&hash(99)));
                assert!(ab.block_buffer.is_empty(), "buffer must be empty after drain");
            }
            _ => panic!("expected AwaitingBlock"),
        }
    }

    #[test]
    fn block_buffer_empty_when_batch_completes() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let genesis_checked = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis_checked.header().block_hash();
        let prev_hash = genesis_checked.header().prev_blockhash;
        let genesis = regtest_genesis_unchecked();

        // Only genesis in the batch. On receipt peer_inventory empties.
        // The download queue is empty (regtest has no headers ahead of genesis),
        // so we transition to AwaitingInv.
        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::from([genesis_hash]),
            block_buffer: HashMap::new(),
            local_tip: prev_hash,
        });

        let (new_state, messages) = process_message(
            state,
            NetworkMessage::Block(genesis),
            &node_state,
        );

        assert!(
            matches!(new_state, PeerStateMachine::AwaitingInv),
            "empty queue should transition to AwaitingInv"
        );
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], NetworkMessage::GetBlocks(_)));
        // If the debug_assert!(block_buffer.is_empty()) had fired, the test
        // would have panicked before reaching this point.
    }

    #[test]
    fn local_tip_carried_into_next_batch() {
        let (_tmp, node_state, _block_rx) = setup_regtest();
        let genesis_checked = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis_checked.header().block_hash();
        let prev_hash = genesis_checked.header().prev_blockhash;
        let genesis = regtest_genesis_unchecked();

        // Seed the download queue with a fake next-batch hash so that when
        // peer_inventory empties the transition goes to a new AwaitingBlock
        // (instead of AwaitingInv) and we can inspect local_tip.
        let fake_next = hash(42);
        node_state.download_queue.lock().unwrap().push_back(fake_next);

        let state = PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: HashSet::from([genesis_hash]),
            block_buffer: HashMap::new(),
            local_tip: prev_hash,
        });

        let (new_state, messages) = process_message(
            state,
            NetworkMessage::Block(genesis),
            &node_state,
        );

        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], NetworkMessage::GetData(_)));
        match new_state {
            PeerStateMachine::AwaitingBlock(ref ab) => {
                assert_eq!(
                    ab.local_tip, genesis_hash,
                    "local_tip must carry forward from the previous batch, not reset to the global tip"
                );
                assert!(ab.peer_inventory.contains(&fake_next));
            }
            _ => panic!("expected AwaitingBlock with next batch"),
        }
    }
}
