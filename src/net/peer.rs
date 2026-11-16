use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt, iter,
    sync::{mpsc, Arc, Mutex},
    thread,
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
use log::{debug, info, log_enabled, warn, Level};
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
pub const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_CHECK_INTERVAL: Duration = Duration::from_millis(100);
/// Measured from the lowest unreceived block.
pub const BLOCK_DOWNLOAD_WINDOW: i32 = 1024;
pub const BLOCK_STALLING_TIMEOUT_DEFAULT: Duration = Duration::from_secs(2);
const BLOCK_STALLING_TIMEOUT_MAX: Duration = Duration::from_secs(64);

// Field order sets the queue order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockId {
    height: i32,
    hash: BlockHash,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Stall {
    block: BlockHash,
    since: Instant,
}

pub struct DownloadState {
    queue: BTreeSet<BlockId>,
    in_flight: HashMap<BlockHash, i32>,
    received: HashSet<BlockHash>,
    stall: Option<Stall>,
    stalling_timeout: Duration,
}

impl Default for DownloadState {
    fn default() -> Self {
        DownloadState {
            queue: BTreeSet::new(),
            in_flight: HashMap::new(),
            received: HashSet::new(),
            stall: None,
            stalling_timeout: BLOCK_STALLING_TIMEOUT_DEFAULT,
        }
    }
}

impl DownloadState {
    fn pop_batch(&mut self, batch_size: usize) -> Vec<BlockHash> {
        let Some(first) = self.queue.first() else {
            return Vec::new();
        };
        let lowest = self
            .in_flight
            .values()
            .copied()
            .fold(first.height, i32::min);
        let mut batch = Vec::with_capacity(batch_size);
        while batch.len() < batch_size {
            let Some(&BlockId { height, hash }) = self.queue.first() else {
                break;
            };
            if height >= lowest + BLOCK_DOWNLOAD_WINDOW {
                break;
            }
            self.queue.pop_first();
            if self.in_flight.insert(hash, height).is_none() {
                batch.push(hash);
            }
        }
        batch
    }

    fn claim(&mut self, blocks: Vec<BlockId>) -> Vec<BlockHash> {
        blocks
            .into_iter()
            .filter(|block| self.in_flight.insert(block.hash, block.height).is_none())
            .map(|block| block.hash)
            .collect()
    }

    fn receive(&mut self, hash: BlockHash) -> bool {
        if self.in_flight.remove(&hash).is_none() {
            return false;
        }
        self.received.insert(hash);
        true
    }

    fn requeue_unreceived(&mut self, inventory: &HashSet<BlockHash>) {
        self.clear_stall_held_by(inventory);
        let mut requeued = 0;
        for hash in inventory {
            if let Some(height) = self.in_flight.remove(hash) {
                self.queue.insert(BlockId {
                    height,
                    hash: *hash,
                });
                requeued += 1;
            }
        }
        if requeued > 0 {
            debug!(target: Category::NET, "Re-enqueued {} unreceived blocks", requeued);
        }
    }

    fn forget_connected(&mut self, active_from_tip: impl IntoIterator<Item = BlockHash>) -> usize {
        let mut connected = 0;
        for hash in active_from_tip {
            if !self.received.remove(&hash) {
                break;
            }
            connected += 1;
        }
        connected
    }

    fn mark_stall(&mut self) {
        if let Some(stall) = &self.stall {
            if self.in_flight.contains_key(&stall.block) {
                return;
            }
        }
        let lowest = self
            .in_flight
            .iter()
            .min_by_key(|(_, &height)| height)
            .map(|(&hash, _)| hash);
        self.stall = lowest.map(|block| {
            debug!(target: Category::NET, "Block {} is holding back the window", block);
            Stall {
                block,
                since: Instant::now(),
            }
        });
    }

    fn clear_stall_held_by(&mut self, inventory: &HashSet<BlockHash>) {
        if self
            .stall
            .as_ref()
            .is_some_and(|stall| inventory.contains(&stall.block))
        {
            self.stall = None;
        }
    }

    fn expire_stall_held_by(&mut self, inventory: &HashSet<BlockHash>) -> bool {
        let Some(stall) = &self.stall else {
            return false;
        };
        if !inventory.contains(&stall.block) || stall.since.elapsed() < self.stalling_timeout {
            return false;
        }
        self.stall = None;
        self.stalling_timeout = (self.stalling_timeout * 2).min(BLOCK_STALLING_TIMEOUT_MAX);
        true
    }

    fn shorten_stalling_timeout(&mut self, blocks_connected: usize) {
        for _ in 0..blocks_connected {
            if self.stalling_timeout <= BLOCK_STALLING_TIMEOUT_DEFAULT {
                break;
            }
            let shorter = Duration::from_secs(self.stalling_timeout.as_secs() * 85 / 100);
            self.stalling_timeout = shorter.max(BLOCK_STALLING_TIMEOUT_DEFAULT);
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
        let connected = state.forget_connected(
            iter::successors(Some(tip), |entry| entry.prev())
                .map(|entry| BlockHash::from_byte_array(entry.block_hash().to_bytes())),
        );
        state.shorten_stalling_timeout(connected);
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
///         │    │  AwaitingBlock  │──┐  batch done + window has more:
///         │    └─────────────────┘◀─┘  take the next batch
///         │       ▲         │
///         │ hdrs/ │         │ batch done AND nothing to take
///         │  idle │         ▼
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
        hashes.push(BlockId {
            height: current.height(),
            hash: BlockHash::from_byte_array(current.block_hash().to_bytes()),
        });
        match current.prev() {
            Some(prev) => current = prev,
            None => return,
        }
    };
    if hashes.is_empty() {
        return;
    }
    let fork_height = best_height - hashes.len() as i32;
    let mut state = download.lock().unwrap();
    if !state.queue.is_empty() {
        return;
    }
    let queued: BTreeSet<BlockId> = hashes
        .into_iter()
        .filter(|block| {
            !state.received.contains(&block.hash) && !state.in_flight.contains_key(&block.hash)
        })
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

fn request_blocks(batch: Vec<BlockHash>) -> (PeerStateMachine, Vec<NetworkMessage>) {
    let message = create_getdata_message(&batch);
    (
        PeerStateMachine::AwaitingBlock(AwaitingBlock {
            peer_inventory: batch.into_iter().collect(),
        }),
        vec![message],
    )
}

fn request_next_batch(node_state: &NodeState) -> (PeerStateMachine, Vec<NetworkMessage>) {
    let mut download = node_state.download.lock().unwrap();
    let batch = download.pop_batch(DOWNLOAD_BATCH_SIZE);
    if !batch.is_empty() {
        return request_blocks(batch);
    }
    // Polling while the window is full would loop.
    if !download.queue.is_empty() {
        download.mark_stall();
        return (PeerStateMachine::AwaitingInv, vec![]);
    }
    drop(download);
    let locators = build_block_locators(node_state.chainman.active_chain().tip());
    (
        PeerStateMachine::AwaitingInv,
        vec![create_getblocks_message(locators)],
    )
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
                    return request_next_batch(node_state);
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
                    let height = node_state
                        .chainman
                        .get_block_tree_entry(&bitcoinkernel::BlockHash::from(
                            block_hash.to_byte_array(),
                        ))
                        .expect("a valid header is in the block tree")
                        .height();
                    announced.push(BlockId {
                        height,
                        hash: block_hash,
                    });
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
                    request_next_batch(node_state)
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

fn process_idle(
    state_machine: PeerStateMachine,
    node_state: &NodeState,
) -> (PeerStateMachine, Vec<NetworkMessage>) {
    if !matches!(state_machine, PeerStateMachine::AwaitingInv) {
        return (state_machine, vec![]);
    }
    let mut download = node_state.download.lock().unwrap();
    let batch = download.pop_batch(DOWNLOAD_BATCH_SIZE);
    if batch.is_empty() {
        if !download.queue.is_empty() {
            download.mark_stall();
        }
        return (PeerStateMachine::AwaitingInv, vec![]);
    }
    drop(download);
    request_blocks(batch)
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

fn read_messages(
    mut reader: ConnectionReader,
    message_tx: mpsc::SyncSender<Result<Option<NetworkMessage>, p2p::net::Error>>,
) {
    loop {
        let message = reader.read_message();
        let failed = message.is_err();
        if message_tx.send(message).is_err() || failed {
            return;
        }
    }
}

pub struct BitcoinPeer {
    dest: Destination,
    writer: Arc<ConnectionWriter>,
    messages: mpsc::Receiver<Result<Option<NetworkMessage>, p2p::net::Error>>,
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
        // Reads stop while the peer thread waits on the kernel.
        let (message_tx, message_rx) = mpsc::sync_channel(0);
        thread::spawn(move || read_messages(reader, message_tx));
        let peer = BitcoinPeer {
            dest: destination,
            writer: Arc::new(writer),
            messages: message_rx,
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

    pub fn holds_back_window(&self, download: &Mutex<DownloadState>) -> bool {
        let PeerStateMachine::AwaitingBlock(state) = &self.state_machine else {
            return false;
        };
        download
            .lock()
            .unwrap()
            .expire_stall_held_by(&state.peer_inventory)
    }

    pub fn release_in_flight(&self, download: &Mutex<DownloadState>) {
        if let PeerStateMachine::AwaitingBlock(state) = &self.state_machine {
            download
                .lock()
                .unwrap()
                .requeue_unreceived(&state.peer_inventory);
        }
    }

    fn receive_message(&mut self) -> Result<Option<NetworkMessage>, p2p::net::Error> {
        match self.messages.recv_timeout(PEER_CHECK_INTERVAL) {
            Ok(message) => Ok(Some(message?.expect("v1 only supported currently"))),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(p2p::net::Error::ChannelClosed),
        }
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &NodeState,
    ) -> Result<(), p2p::net::Error> {
        let msg = self.receive_message()?;
        if let Some(NetworkMessage::Block(block)) = &msg {
            debug!(target: Category::NET, "Received block {} from {}", block.block_hash(), self);
        }
        let delivered = msg
            .as_ref()
            .is_some_and(|msg| delivers_requested_block(&self.state_machine, msg));
        if let PeerStateMachine::AwaitingBlock(state) = &self.state_machine {
            if delivered {
                node_state
                    .download
                    .lock()
                    .unwrap()
                    .clear_stall_held_by(&state.peer_inventory);
            }
        }
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) = match msg {
            Some(msg) => process_message(old_state, msg, &self.dest.addr, node_state),
            None => process_idle(old_state, node_state),
        };
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
            if log_enabled!(target: Category::NET, Level::Debug) {
                if let NetworkMessage::GetData(inventory) = &message {
                    for item in inventory {
                        if let Inventory::WitnessBlock(hash) = item {
                            debug!(target: Category::NET, "Requesting block {} from {}", hash, self);
                        }
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

    fn block_id(hash: BlockHash) -> BlockId {
        BlockId {
            height: i32::from(hash.to_byte_array()[0]),
            hash,
        }
    }

    fn download(queue: &[BlockHash], in_flight: &[BlockHash]) -> DownloadState {
        DownloadState {
            queue: queue.iter().map(|&hash| block_id(hash)).collect(),
            in_flight: in_flight
                .iter()
                .map(|&hash| (hash, block_id(hash).height))
                .collect(),
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
        assert_eq!(d.in_flight, HashMap::from([(hash(1), 1), (hash(2), 2)]));
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
    fn pop_batch_stays_within_the_window() {
        let mut d = DownloadState {
            queue: BTreeSet::from([
                BlockId {
                    height: 1,
                    hash: hash(1),
                },
                BlockId {
                    height: BLOCK_DOWNLOAD_WINDOW,
                    hash: hash(2),
                },
                BlockId {
                    height: BLOCK_DOWNLOAD_WINDOW + 1,
                    hash: hash(3),
                },
            ]),
            ..Default::default()
        };
        assert_eq!(d.pop_batch(16), vec![hash(1), hash(2)]);
        assert!(d.pop_batch(16).is_empty());
        assert!(d.receive(hash(1)));
        assert_eq!(d.pop_batch(16), vec![hash(3)]);
    }

    #[test]
    fn pop_batch_preserves_height_order() {
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
        assert_eq!(
            d.queue,
            BTreeSet::from([1, 2, 5, 6].map(|n| block_id(hash(n))))
        );
        assert_eq!(d.in_flight, HashMap::from([(hash(3), 3)]));
    }

    #[test]
    fn requeue_unreceived_orders_by_height() {
        let mut d = download(&[hash(9)], &[hash(1), hash(2), hash(5), hash(6)]);
        d.requeue_unreceived(&HashSet::from([hash(1), hash(2)]));
        d.requeue_unreceived(&HashSet::from([hash(5), hash(6)]));
        assert_eq!(
            d.pop_batch(16),
            vec![hash(1), hash(2), hash(5), hash(6), hash(9)]
        );
    }

    #[test]
    fn requeue_unreceived_skips_blocks_already_received() {
        let mut d = download(&[], &[hash(1), hash(2)]);
        assert!(d.receive(hash(1)));
        d.requeue_unreceived(&HashSet::from([hash(1), hash(2)]));
        assert_eq!(d.queue, BTreeSet::from([block_id(hash(2))]));
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
        assert_eq!(d.in_flight, HashMap::from([(hash(2), 2)]));
    }

    #[test]
    fn forget_connected_stops_at_first_hash_not_received() {
        let mut d = DownloadState {
            received: HashSet::from([hash(1), hash(3), hash(4)]),
            ..Default::default()
        };
        assert_eq!(d.forget_connected([hash(4), hash(3), hash(2), hash(1)]), 2);
        assert_eq!(d.received, HashSet::from([hash(1)]));
    }

    fn stalled_for(block: BlockHash, elapsed: Duration) -> Option<Stall> {
        Some(Stall {
            block,
            since: Instant::now() - elapsed,
        })
    }

    #[test]
    fn mark_stall_marks_the_lowest_block_in_flight() {
        let mut d = download(&[hash(9)], &[hash(5), hash(3)]);
        d.mark_stall();
        let marked = d.stall;
        assert_eq!(marked.map(|stall| stall.block), Some(hash(3)));
        d.mark_stall();
        assert_eq!(d.stall, marked);
    }

    #[test]
    fn mark_stall_moves_on_once_the_block_arrives() {
        let mut d = download(&[hash(9)], &[hash(3), hash(5)]);
        d.mark_stall();
        assert!(d.receive(hash(3)));
        d.mark_stall();
        assert_eq!(d.stall.map(|stall| stall.block), Some(hash(5)));
    }

    #[test]
    fn expire_stall_waits_for_the_timeout() {
        let mut d = download(&[], &[hash(3)]);
        d.mark_stall();
        assert!(!d.expire_stall_held_by(&HashSet::from([hash(3)])));
        assert!(d.stall.is_some());
    }

    #[test]
    fn expire_stall_drops_only_the_holder() {
        let mut d = download(&[], &[hash(3)]);
        d.stall = stalled_for(hash(3), BLOCK_STALLING_TIMEOUT_DEFAULT * 2);
        assert!(!d.expire_stall_held_by(&HashSet::from([hash(4)])));
        assert!(d.expire_stall_held_by(&HashSet::from([hash(3)])));
        assert_eq!(d.stall, None);
        assert_eq!(d.stalling_timeout, BLOCK_STALLING_TIMEOUT_DEFAULT * 2);
    }

    #[test]
    fn stalling_timeout_doubles_up_to_the_max() {
        let mut d = download(&[], &[hash(3)]);
        d.stalling_timeout = Duration::from_secs(40);
        d.stall = stalled_for(hash(3), Duration::from_secs(41));
        assert!(d.expire_stall_held_by(&HashSet::from([hash(3)])));
        assert_eq!(d.stalling_timeout, BLOCK_STALLING_TIMEOUT_MAX);
    }

    #[test]
    fn stalling_timeout_shrinks_as_blocks_connect() {
        let mut d = DownloadState {
            stalling_timeout: Duration::from_secs(8),
            ..Default::default()
        };
        d.shorten_stalling_timeout(1);
        assert_eq!(d.stalling_timeout, Duration::from_secs(6));
        d.shorten_stalling_timeout(100);
        assert_eq!(d.stalling_timeout, BLOCK_STALLING_TIMEOUT_DEFAULT);
    }

    #[test]
    fn stall_clears_when_its_holder_delivers_or_leaves() {
        let mut d = download(&[], &[hash(3), hash(4)]);
        d.mark_stall();
        d.clear_stall_held_by(&HashSet::from([hash(4)]));
        assert!(d.stall.is_some());
        d.clear_stall_held_by(&HashSet::from([hash(3)]));
        assert_eq!(d.stall, None);
        d.mark_stall();
        d.requeue_unreceived(&HashSet::from([hash(3)]));
        assert_eq!(d.stall, None);
    }
}
