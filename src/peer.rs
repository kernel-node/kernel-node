use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    net::SocketAddr,
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use bitcoin::{BlockHash, Network};
use bitcoinkernel::{ChainstateManager, Context, ProcessBlockHeaderResult, ValidationMode, core::BlockHashExt, prelude::BlockValidationStateExt};
use log::{debug, error, info, warn};
use p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, ConnectionReader, ConnectionWriter, TimeoutParams},
    p2p_message_types::{
        address::AddrV2, Address, ProtocolVersion, ServiceFlags,
        message::{AddrV2Payload, InventoryPayload, NetworkMessage},
        message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory},
        message_network::UserAgent,
    },
};

use crate::kernel_util::{bitcoin_block_to_kernel_block, bitcoin_header_to_kernel_header};

const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::INVALID_CB_NO_BAN_VERSION;

/// Number of blocks each peer requests per batch from the download queue.
const DOWNLOAD_BATCH_SIZE: usize = 16;

/// If a peer stays in AwaitingBlock for this long without receiving any
/// block, it is considered stalled and disconnected.
const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Walk backwards from the header tip to the active chain tip, collecting
/// block hashes into the download queue. Only populates if the queue is empty.
fn populate_download_queue(chainman: &ChainstateManager, queue: &Mutex<VecDeque<BlockHash>>) {
    let mut q = queue.lock().unwrap();
    if !q.is_empty() {
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
    info!("Built download queue with {} blocks (heights {} to {})", hashes.len(), active_height + 1, best_height);
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
}

fn create_getheaders_message(known_block_hash: bitcoin::BlockHash) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage {
        version: PROTOCOL_VERSION,
        locator_hashes: vec![known_block_hash],
        stop_hash: bitcoin::BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
    })
}

fn create_getblocks_message(known_block_hash: bitcoin::BlockHash) -> NetworkMessage {
    NetworkMessage::GetBlocks(GetBlocksMessage {
        version: PROTOCOL_VERSION,
        locator_hashes: vec![known_block_hash],
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
                    let result = node_state.chainman.process_block_header(&bitcoin_header_to_kernel_header(&header));
                    match result {
                        ProcessBlockHeaderResult::Success(state) if state.mode() == ValidationMode::Valid => {
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
                    // Headers sync complete. Build the download queue from
                    // the header chain and start downloading directly.
                    populate_download_queue(&node_state.chainman, &node_state.download_queue);
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
                            }),
                            vec![create_getdata_message(&batch)],
                        );
                    }
                    // Queue empty (already caught up). Fall back to inv-based sync.
                    let tip_hash = node_state.get_tip_state().block_hash;
                    return (PeerStateMachine::AwaitingInv, vec![create_getblocks_message(tip_hash)]);
                }

                let best_hash = BlockHash::from_byte_array(node_state.chainman.best_entry().unwrap().block_hash().to_bytes());
                (PeerStateMachine::AwaitingHeaders, vec![create_getheaders_message(best_hash)])
            }
            message => {
                debug!("Ignoring message: {:?}", message);
                (PeerStateMachine::AwaitingHeaders, vec![])
            }
        }
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
                    // Claim only blocks not already being downloaded by another peer.
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
                            }),
                            vec![create_getdata_message(&claimed)],
                        )
                    } else {
                        // All blocks already claimed by other peers.
                        // Re-request from current tip; network round-trip
                        // gives other peers time to finish.
                        let our_best = node_state.get_tip_state().block_hash;
                        (PeerStateMachine::AwaitingInv, vec![create_getblocks_message(our_best)])
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
                // Release from global in-flight set now that we have the block.
                node_state.in_flight_blocks.lock().unwrap().remove(&block_hash);
                block_state
                    .block_buffer
                    .insert(prev_blockhash, bitcoin_block_to_kernel_block(&block));

                while let Some(next_block) = block_state
                    .block_buffer
                    .remove(&node_state.get_tip_state().block_hash)
                {
                    if let Err(err) = node_state.block_tx.send(next_block) {
                        debug!("Encountered error on block send: {}", err);
                        return (PeerStateMachine::AwaitingBlock(block_state), vec![]);
                    }
                }

                // If all expected blocks were received, clear any remaining
                // blocks in the buffer and request the next batch.
                if block_state.peer_inventory.is_empty() {
                    block_state.block_buffer.clear();
                    // Try to get the next batch from the download queue.
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
                            }),
                            vec![create_getdata_message(&batch)],
                        )
                    } else {
                        // Queue exhausted. Fall back to inv-based sync.
                        let our_best = node_state.get_tip_state().block_hash;
                        (
                            PeerStateMachine::AwaitingInv,
                            vec![create_getblocks_message(our_best)],
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
        let state_machine = PeerStateMachine::AwaitingHeaders;
        let best_hash = BlockHash::from_byte_array(node_state.chainman.best_entry().unwrap().block_hash().to_bytes());
        let getheaders = create_getheaders_message(best_hash);
        debug!("sending headers message...");
        writer.send_message(getheaders)?;
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

    /// Release any block hashes this peer claimed but never received.
    /// Called when the peer disconnects to unblock other peers.
    pub fn release_in_flight(&self, in_flight: &Mutex<HashSet<BlockHash>>) {
        if let PeerStateMachine::AwaitingBlock(ref state) = self.state_machine {
            let mut set = in_flight.lock().unwrap();
            for hash in &state.peer_inventory {
                set.remove(hash);
            }
        }
    }

    /// Returns true if this peer is in AwaitingBlock state and has not
    /// made progress (received a block) within PEER_STALL_TIMEOUT.
    pub fn is_stalled(&self) -> bool {
        matches!(self.state_machine, PeerStateMachine::AwaitingBlock(_))
            && self.last_progress.elapsed() > PEER_STALL_TIMEOUT
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &NodeState,
    ) -> Result<(), p2p::net::Error> {
        let msg = self.receive_message()?;
        // A block message means the peer is making progress.
        let is_block = matches!(msg, NetworkMessage::Block(_));
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) = process_message(old_state, msg, node_state);
        self.state_machine = peer_state_machine;

        if is_block {
            self.last_progress = Instant::now();
        }

        for message in messages.drain(..) {
            self.writer.send_message(message)?
        }
        Ok(())
    }
}

/// The default number of concurrent peer connections during IBD.
const DEFAULT_MAX_PEERS: usize = 4;

/// Manages multiple concurrent peer connections.
///
/// Each peer runs in its own thread, independently downloading headers and
/// blocks. All peers share the same NodeState, so blocks from any peer flow
/// into the same processing pipeline. When a peer disconnects, the manager
/// automatically replaces it with a new connection.
pub struct PeerManager {
    /// Maximum number of concurrent peer connections.
    max_peers: usize,
    /// Address manager for selecting peers.
    addrman: Arc<Mutex<addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>>>,
    /// Shared node state (channels, chain state, etc.).
    node_state: Arc<NodeState>,
    /// The bitcoin network we're connecting to.
    network: Network,
    /// Flag to signal all peer threads to stop.
    running: Arc<AtomicBool>,
    /// Handles for spawned peer threads.
    peer_threads: Vec<thread::JoinHandle<()>>,
    /// Writers for each active peer, used to kill connections on shutdown.
    /// Each slot corresponds to a peer thread index.
    peer_writers: Vec<Arc<Mutex<Option<Arc<ConnectionWriter>>>>>,
    /// Tracks which peer addresses are currently connected, preventing
    /// multiple threads from connecting to the same peer.
    connected_peers: Arc<Mutex<HashSet<SocketAddr>>>,
}

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

impl PeerManager {
    /// Create a new PeerManager.
    ///
    /// `addrman` should already be populated with seed addresses.
    /// `node_state` is shared across all peer threads.
    pub fn new(
        addrman: addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>,
        node_state: Arc<NodeState>,
        network: Network,
    ) -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            addrman: Arc::new(Mutex::new(addrman)),
            node_state,
            network,
            running: Arc::new(AtomicBool::new(true)),
            peer_threads: Vec::new(),
            peer_writers: Vec::new(),
            connected_peers: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Set the maximum number of concurrent peer connections.
    pub fn max_peers(mut self, n: usize) -> Self {
        self.max_peers = n;
        self
    }

    /// Returns a reference to the shared address manager.
    pub fn addrman(&self) -> &Arc<Mutex<addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>>> {
        &self.addrman
    }

    /// Returns the running flag (used by block processing thread for stale detection).
    pub fn running(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Returns writer handles for all peer slots (used by stale block detection
    /// to kill slow peers).
    pub fn peer_writers(&self) -> &[Arc<Mutex<Option<Arc<ConnectionWriter>>>>] {
        &self.peer_writers
    }

    /// Spawn all peer threads.
    ///
    /// Each thread runs a loop: select a peer from addrman, connect, process
    /// messages until error, then try the next peer. This continues until
    /// `stop()` is called.
    pub fn start(&mut self) {
        info!("Starting peer manager with {} max peers", self.max_peers);
        for i in 0..self.max_peers {
            let running = Arc::clone(&self.running);
            let addrman = Arc::clone(&self.addrman);
            let node_state = Arc::clone(&self.node_state);
            let network = self.network;
            let writer_slot: Arc<Mutex<Option<Arc<ConnectionWriter>>>> =
                Arc::new(Mutex::new(None));
            let writer_slot_clone = Arc::clone(&writer_slot);
            self.peer_writers.push(writer_slot);

            let connected_peers = Arc::clone(&self.connected_peers);

            let handle = thread::spawn(move || {
                info!("Peer thread {} started", i);
                while running.load(Ordering::SeqCst) {
                    let socket_addr = {
                        let addr_lock = addrman.lock().unwrap();
                        let (address, port) = match addr_lock.select() {
                            Some(record) => record.network_addr(),
                            None => {
                                drop(addr_lock);
                                thread::sleep(Duration::from_secs(1));
                                continue;
                            }
                        };
                        match address {
                            AddrV2::Ipv4(ipv4) => {
                                SocketAddr::V4(std::net::SocketAddrV4::new(ipv4, port))
                            }
                            AddrV2::Ipv6(ipv6) => {
                                SocketAddr::from((ipv6, port))
                            }
                            _ => continue,
                        }
                    };

                    // Skip if another thread is already connected to this peer.
                    {
                        let mut peers = connected_peers.lock().unwrap();
                        if peers.contains(&socket_addr) {
                            debug!("Peer thread {}: skipping {} (already connected)", i, socket_addr);
                            continue;
                        }
                        peers.insert(socket_addr);
                    }

                    let peer = BitcoinPeer::new(socket_addr, network, &node_state);
                    let mut peer = match peer {
                        Ok(connection) => {
                            let mut w = writer_slot_clone.lock().unwrap();
                            *w = Some(connection.writer());
                            connection
                        }
                        Err(e) => {
                            error!("Peer thread {}: could not connect to {}: {}", i, socket_addr, e);
                            connected_peers.lock().unwrap().remove(&socket_addr);
                            thread::sleep(Duration::from_millis(500));
                            continue;
                        }
                    };

                    info!("Peer thread {}: connected to {}", i, peer);
                    loop {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        if peer.is_stalled() {
                            warn!("Peer thread {}: stalled waiting for blocks, disconnecting {}", i, peer);
                            break;
                        }
                        if let Err(e) = peer.receive_and_process_message(&node_state) {
                            match e {
                                p2p::net::Error::Io(io) => {
                                    if io.kind() != std::io::ErrorKind::UnexpectedEof {
                                        error!("Peer thread {}: I/O error: {}", i, io);
                                    }
                                }
                                e => error!("Peer thread {}: error: {}", i, e),
                            }
                            break;
                        }
                    }
                    // Release any blocks this peer claimed but never received.
                    peer.release_in_flight(&node_state.in_flight_blocks);
                    // Remove from connected set and clear writer.
                    connected_peers.lock().unwrap().remove(&socket_addr);
                    let mut w = writer_slot_clone.lock().unwrap();
                    *w = None;
                }
                info!("Peer thread {} stopped", i);
            });

            self.peer_threads.push(handle);
        }
    }

    /// Signal all peer threads to stop and kill active connections.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        for writer_slot in &self.peer_writers {
            let mut w = writer_slot.lock().unwrap();
            if let Some(conn) = w.deref_mut() {
                let _ = conn.shutdown();
            }
        }
    }

    /// Wait for all peer threads to finish. Call `stop()` first.
    pub fn join(self) {
        for handle in self.peer_threads {
            let _ = handle.join();
        }
    }
}
