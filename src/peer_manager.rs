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

use bitcoin::{p2p::address::AddrV2, Network};
use log::{debug, error, info};
use p2p::net::ConnectionWriter;

use crate::{
    logging::Category,
    peer::{BitcoinPeer, NodeState},
};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

pub type AddrTable = addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>;

const DEFAULT_MAX_PEERS: usize = 4;

pub struct PeerManager {
    max_peers: usize,
    addrman: Arc<Mutex<AddrTable>>,
    node_state: Arc<NodeState>,
    network: Network,
    running: Arc<AtomicBool>,
    peer_threads: Vec<thread::JoinHandle<()>>,
    peer_writers: Vec<Arc<Mutex<Option<Arc<ConnectionWriter>>>>>,
    connected_peers: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl PeerManager {
    pub fn new(
        addrman: Arc<Mutex<AddrTable>>,
        node_state: Arc<NodeState>,
        network: Network,
    ) -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            addrman,
            node_state,
            network,
            running: Arc::new(AtomicBool::new(true)),
            peer_threads: Vec::new(),
            peer_writers: Vec::new(),
            connected_peers: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn max_peers(mut self, n: usize) -> Self {
        self.max_peers = n.max(1);
        self
    }

    pub fn peer_writers(&self) -> &[Arc<Mutex<Option<Arc<ConnectionWriter>>>>] {
        &self.peer_writers
    }

    pub fn start(&mut self) {
        info!(target: Category::NET, "Starting peer manager with {} peers", self.max_peers);
        for i in 0..self.max_peers {
            let running = Arc::clone(&self.running);
            let addrman = Arc::clone(&self.addrman);
            let node_state = Arc::clone(&self.node_state);
            let network = self.network;
            let writer_slot: Arc<Mutex<Option<Arc<ConnectionWriter>>>> = Arc::new(Mutex::new(None));
            let writer_slot_thread = Arc::clone(&writer_slot);
            self.peer_writers.push(writer_slot);
            let connected_peers = Arc::clone(&self.connected_peers);

            let handle = thread::spawn(move || {
                info!(target: Category::NET, "Peer thread {} started", i);
                while running.load(Ordering::SeqCst) {
                    let selected = {
                        let table = addrman.lock().unwrap();
                        table.select().map(|record| record.network_addr())
                    };
                    let socket_addr = match selected {
                        Some((AddrV2::Ipv4(ipv4), port)) => SocketAddr::from((ipv4, port)),
                        Some((AddrV2::Ipv6(ipv6), port)) => SocketAddr::from((ipv6, port)),
                        Some(_) => continue,
                        None => {
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    };

                    {
                        let mut connected = connected_peers.lock().unwrap();
                        if !connected.insert(socket_addr) {
                            drop(connected);
                            debug!(target: Category::NET, "Peer thread {}: {} already connected", i, socket_addr);
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    }

                    let mut peer = match BitcoinPeer::new(socket_addr, network, &node_state) {
                        Ok(peer) => {
                            *writer_slot_thread.lock().unwrap() = Some(peer.writer());
                            peer
                        }
                        Err(e) => {
                            error!(target: Category::NET, "Peer thread {}: could not connect to {}: {}", i, socket_addr, e);
                            connected_peers.lock().unwrap().remove(&socket_addr);
                            thread::sleep(Duration::from_millis(500));
                            continue;
                        }
                    };

                    info!(target: Category::NET, "Peer thread {}: connected to {}", i, peer);
                    while running.load(Ordering::SeqCst) {
                        if let Err(e) = peer.receive_and_process_message(&node_state) {
                            match e {
                                p2p::net::Error::Io(io)
                                    if io.kind() == std::io::ErrorKind::UnexpectedEof => {}
                                p2p::net::Error::Io(io) => {
                                    error!(target: Category::NET, "Peer thread {}: I/O error: {}", i, io)
                                }
                                e => {
                                    error!(target: Category::NET, "Peer thread {}: error: {}", i, e)
                                }
                            }
                            break;
                        }
                    }

                    peer.release_in_flight(&node_state.download);
                    connected_peers.lock().unwrap().remove(&socket_addr);
                    *writer_slot_thread.lock().unwrap() = None;
                }
                info!(target: Category::NET, "Peer thread {} stopped", i);
            });
            self.peer_threads.push(handle);
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        for writer_slot in &self.peer_writers {
            if let Some(conn) = writer_slot.lock().unwrap().deref_mut() {
                let _ = conn.shutdown();
            }
        }
    }

    pub fn join(self) {
        for handle in self.peer_threads {
            let _ = handle.join();
        }
    }
}
