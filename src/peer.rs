use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    sync::{mpsc, Arc, Mutex},
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
///       [*]
///        │
/// AwaitingHeaders
///        ▼
///   AwaitingInv
///       ▲ |
/// Block | | Inv
///       | ▼
///   AwaitingBlock
///       │ ▲
///       │ │
///       └─┘
///      Block
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

/// Logarithmic spacing lets the remote peer find the fork point efficiently
/// even after a deep reorg.
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
    node_state: &mut NodeState,
) -> (PeerStateMachine, Vec<NetworkMessage>) {
    // Always process the ping first as a special case.
    if let NetworkMessage::Ping(nonce) = event {
        info!("Received ping, responding pong.");
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
                    debug!("Requesting {} blocks", block_hashes.len());
                    (
                        PeerStateMachine::AwaitingBlock(AwaitingBlock {
                            peer_inventory: block_hashes.iter().cloned().collect(),
                            block_buffer: HashMap::new(),
                        }),
                        vec![create_getdata_message(&block_hashes)],
                    )
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
                let prev_blockhash = block.header().prev_blockhash;
                block_state.peer_inventory.remove(&block.block_hash());
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

                // If all to be expected blocks were received, clear any
                // remaining blocks in the buffer and request a fresh batch of
                // blocks.
                if block_state.peer_inventory.is_empty() {
                    block_state.block_buffer.clear();
                    let locator = build_block_locator(&node_state.chainman);
                    (
                        PeerStateMachine::AwaitingInv,
                        vec![create_getblocks_message(locator)],
                    )
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
        node_state: &mut NodeState,
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
        let locator = build_block_locator(&node_state.chainman);
        writer.send_message(create_getheaders_message(locator))?;
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

    fn receive_message(&mut self) -> Result<NetworkMessage, p2p::net::Error> {
        Ok(self
            .reader
            .read_message()?
            .expect("v1 only supported currently"))
    }

    pub fn receive_and_process_message(
        &mut self,
        node_state: &mut NodeState,
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
}
