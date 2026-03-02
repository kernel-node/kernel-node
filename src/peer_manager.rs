use std::{
    collections::HashSet,
    net::SocketAddr,
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use bitcoin::Network;
use log::{debug, error, info, warn};
use p2p::{net::ConnectionWriter, p2p_message_types::address::AddrV2};

use crate::peer::{BitcoinPeer, NodeState};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

/// Concrete addrman table type used by PeerManager.
/// Exported so callers can construct a table without repeating the const values.
pub type AddrTable = addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>;

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
    addrman: Arc<Mutex<AddrTable>>,
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

impl PeerManager {
    /// Create a new PeerManager.
    ///
    /// `addrman` should already be populated with seed addresses.
    /// `node_state` is shared across all peer threads.
    pub fn new(addrman: AddrTable, node_state: Arc<NodeState>, network: Network) -> Self {
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
    pub fn addrman(&self) -> &Arc<Mutex<AddrTable>> {
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
            let writer_slot: Arc<Mutex<Option<Arc<ConnectionWriter>>>> = Arc::new(Mutex::new(None));
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
                            AddrV2::Ipv6(ipv6) => SocketAddr::from((ipv6, port)),
                            _ => continue,
                        }
                    };

                    {
                        let mut peers = connected_peers.lock().unwrap();
                        if peers.contains(&socket_addr) {
                            debug!(
                                "Peer thread {}: skipping {} (already connected)",
                                i, socket_addr
                            );
                            drop(peers);
                            thread::sleep(Duration::from_secs(1));
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
                            error!(
                                "Peer thread {}: could not connect to {}: {}",
                                i, socket_addr, e
                            );
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
                            warn!(
                                "Peer thread {}: stalled waiting for blocks, disconnecting {}",
                                i, peer
                            );
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
                    peer.release_in_flight(
                        &node_state.download_queue,
                        &node_state.in_flight_blocks,
                    );
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
