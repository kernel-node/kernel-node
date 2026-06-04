use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    net::SocketAddr,
    sync::{mpsc, Arc, Mutex},
};

use bitcoin::{
    hashes::Hash,
    p2p::{
        address::AddrV2Message,
        message::NetworkMessage,
        message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory},
        Address, ServiceFlags,
    },
};
use bitcoin::{BlockHash, Network};
use bitcoinkernel::{
    core::BlockHashExt, BlockTreeEntry, ChainstateManager, Context, ProcessBlockHeaderResult,
};
use log::{debug, info, warn};
use p2p::{
    handshake::{ConnectionConfig, ProtocolVersion},
    net::{ConnectionExt, ConnectionReader, ConnectionWriter, TimeoutParams},
};

use crate::{
    ext::{CrateBlockExt, CrateHeaderExt},
    logging::Category,
};

const PROTOCOL_VERSION: ProtocolVersion = 70015;
const MAX_LOCATOR_HASHES: usize = 101;
const DOWNLOAD_BATCH_SIZE: usize = 16;

#[derive(Clone)]
pub struct TipState {
    pub block_hash: bitcoin::BlockHash,
}

impl Default for TipState {
    fn default() -> Self {
        Self {
            block_hash: BlockHash::all_zeros(),
        }
    }
}

pub struct DownloadState {
    queue: VecDeque<BlockHash>,
    in_flight: HashSet<BlockHash>,
    buffer: HashMap<BlockHash, bitcoinkernel::Block>,
    next: BlockHash,
}

impl Default for DownloadState {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            in_flight: HashSet::new(),
            buffer: HashMap::new(),
            next: BlockHash::all_zeros(),
        }
    }
}

impl DownloadState {
    // btck_ValidationInterfaceActiveTipChange could keep next in step with the kernel's
    // tip, rather than seeding it once at startup.
    fn seed_tip(&mut self, tip: BlockHash) {
        self.next = tip;
    }

    // populate_download_queue calls reanchor_to because checking a
    // parent against the active chain needs get_block_tree_entry,
    // which always returns None in bitcoinkernel 0.2.0.
    // btck_ValidationInterfaceUpdatedBlockTip would supply the fork point directly.
    fn reanchor_to(&mut self, fork_point: BlockHash) {
        if self.next == fork_point {
            return;
        }
        debug!(target: Category::NET, "Re-anchoring block buffer to {}", fork_point);
        self.next = fork_point;
    }

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

    fn release(&mut self, hash: &BlockHash) -> bool {
        self.in_flight.remove(hash)
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

    fn buffer_and_drain(
        &mut self,
        prev_blockhash: BlockHash,
        block: bitcoinkernel::Block,
        block_tx: &mpsc::SyncSender<bitcoinkernel::Block>,
    ) {
        self.buffer.insert(prev_blockhash, block);
        while let Some(next_block) = self.buffer.remove(&self.next) {
            self.next = BlockHash::from_byte_array(next_block.hash().into());
            if let Err(err) = block_tx.send(next_block) {
                debug!(target: Category::NODE, "Encountered error on block send: {}", err);
                break;
            }
        }
    }
}

pub struct NodeState {
    pub addr_tx: mpsc::Sender<Vec<AddrV2Message>>,
    pub block_tx: mpsc::SyncSender<bitcoinkernel::Block>,
    pub tip_state: Arc<Mutex<TipState>>,
    pub context: Arc<Context>,
    pub chainman: Arc<ChainstateManager>,
    pub download: Mutex<DownloadState>,
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

    pub fn seed_download_tip(&self, tip: bitcoin::BlockHash) {
        self.download.lock().unwrap().seed_tip(tip);
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
    let mut entry = tip;
    let mut current_height = height as usize;
    let mut step: usize = 1;
    loop {
        let hash = BlockHash::from_byte_array(entry.block_hash().to_bytes());
        locators.push(hash);
        if current_height == 0 || locators.len() >= MAX_LOCATOR_HASHES {
            break;
        }
        if locators.len() > 10 {
            step *= 2;
        }
        let target = current_height.saturating_sub(step);
        while current_height > target {
            match entry.prev() {
                Some(prev) => {
                    entry = prev;
                    current_height -= 1;
                }
                None => break,
            }
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
    info!(
        target: Category::NET,
        "Built download queue with {} blocks (heights {} to {}) forking at {}",
        hashes.len(),
        fork_height + 1,
        best_height,
        fork_point
    );
    state.reanchor_to(fork_point);
    state.queue = VecDeque::from(hashes);
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
        let _ = node_state.addr_tx.send(payload);
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
                    // Get headers so populate_download_queue can use block tree entries because
                    // get_block_tree_entry always returns None in bitcoinkernel 0.2.0.
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
                let prev_blockhash = block.header.prev_blockhash;
                block_state.peer_inventory.remove(&block_hash);
                {
                    let mut download = node_state.download.lock().unwrap();
                    if download.release(&block_hash) {
                        download.buffer_and_drain(
                            prev_blockhash,
                            block.convert(),
                            &node_state.block_tx,
                        );
                    }
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

pub struct BitcoinPeer {
    addr: Address,
    writer: Arc<ConnectionWriter>,
    reader: ConnectionReader,
    state_machine: PeerStateMachine,
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
            .user_agent("/kernel-node:0.1.0/".into());
        let (writer, reader, _) = conf.open_connection(socket_addr, TimeoutParams::new())?;

        let addr = Address::new(&socket_addr, ServiceFlags::WITNESS);
        info!(target: Category::NET, "Connected to {:?}", addr);
        let locators = build_block_locators(node_state.chainman.best_entry().unwrap());
        debug!(target: Category::NET, "Sending headers message...");
        writer.send_message(create_getheaders_message(locators))?;
        let peer = BitcoinPeer {
            addr,
            writer: Arc::new(writer),
            reader,
            state_machine: PeerStateMachine::AwaitingHeaders,
        };
        Ok(peer)
    }

    pub fn writer(&self) -> Arc<ConnectionWriter> {
        Arc::clone(&self.writer)
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
        let old_state = std::mem::take(&mut self.state_machine);
        let (peer_state_machine, mut messages) = process_message(old_state, msg, node_state);
        self.state_machine = peer_state_machine;
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
    fn release_reports_in_flight_membership() {
        let mut d = download(&[hash(1)], &[]);
        assert!(!d.release(&hash(1)));
        d.pop_batch(1);
        assert!(d.release(&hash(1)));
        assert!(!d.release(&hash(1)));
        assert!(!d.release(&hash(2)));
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
    fn reanchor_drains_a_competing_branch_from_the_fork_point() {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
        let branch = block_chain(3);
        let expected: Vec<BlockHash> = branch.iter().map(|b| b.block_hash()).collect();

        let (tx, rx) = mpsc::sync_channel(branch.len());
        let mut d = DownloadState::default();
        d.seed_tip(hash(9));

        d.reanchor_to(genesis);
        for block in &branch {
            d.buffer_and_drain(block.header.prev_blockhash, block.clone().convert(), &tx);
        }
        drop(tx);

        let received: Vec<BlockHash> = rx
            .iter()
            .map(|b| BlockHash::from_byte_array(b.hash().into()))
            .collect();
        assert_eq!(received, expected);
    }

    #[test]
    fn reanchor_to_the_current_tip_is_a_noop() {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
        let mut d = DownloadState::default();
        d.seed_tip(genesis);

        d.reanchor_to(genesis);

        assert_eq!(d.next, genesis);
    }

    #[test]
    fn buffer_drains_in_chain_order_despite_out_of_order_arrivals() {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
        let blocks = block_chain(4);
        let expected: Vec<BlockHash> = blocks.iter().map(|b| b.block_hash()).collect();

        let (tx, rx) = mpsc::sync_channel(blocks.len());
        let mut d = DownloadState::default();
        d.seed_tip(genesis);

        for i in [1, 3, 0, 2] {
            d.buffer_and_drain(
                blocks[i].header.prev_blockhash,
                blocks[i].clone().convert(),
                &tx,
            );
        }
        drop(tx);

        let received: Vec<BlockHash> = rx
            .iter()
            .map(|b| BlockHash::from_byte_array(b.hash().into()))
            .collect();
        assert_eq!(received, expected);
    }

    #[test]
    fn buffer_holds_blocks_until_parent_arrives() {
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
        let blocks = block_chain(2);

        let (tx, rx) = mpsc::sync_channel(blocks.len());
        let mut d = DownloadState::default();
        d.seed_tip(genesis);

        d.buffer_and_drain(
            blocks[1].header.prev_blockhash,
            blocks[1].clone().convert(),
            &tx,
        );
        assert!(rx.try_recv().is_err());

        d.buffer_and_drain(
            blocks[0].header.prev_blockhash,
            blocks[0].clone().convert(),
            &tx,
        );
        drop(tx);
        let received: Vec<BlockHash> = rx
            .iter()
            .map(|b| BlockHash::from_byte_array(b.hash().into()))
            .collect();
        assert_eq!(
            received,
            vec![blocks[0].block_hash(), blocks[1].block_hash()]
        );
    }
}
