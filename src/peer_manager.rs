use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
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
    socks5::{OnionAddress, Socks5Proxy},
    FatalShutdown,
};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

pub type AddrTable = addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>;

const DEFAULT_MAX_PEERS: usize = 8;

/// Consecutive one second waits on an empty address book before giving up.
/// Nothing refills it without a working network, so waiting longer only
/// hides the problem.
const EMPTY_ADDRESS_BOOK_LIMIT: u32 = 60;

pub struct PeerManager {
    max_peers: usize,
    fatal: FatalShutdown,
    addrman: Arc<Mutex<AddrTable>>,
    node_state: Arc<NodeState>,
    network: Network,
    running: Arc<AtomicBool>,
    peer_threads: Vec<thread::JoinHandle<()>>,
    peer_writers: Vec<Arc<Mutex<Option<Arc<ConnectionWriter>>>>>,
    connected_peers: Arc<Mutex<HashSet<Destination>>>,
    proxy: Option<Socks5Proxy>,
}

impl PeerManager {
    pub fn new(
        addrman: Arc<Mutex<AddrTable>>,
        node_state: Arc<NodeState>,
        network: Network,
        fatal: FatalShutdown,
    ) -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            fatal,
            addrman,
            node_state,
            network,
            running: Arc::new(AtomicBool::new(true)),
            peer_threads: Vec::new(),
            peer_writers: Vec::new(),
            connected_peers: Arc::new(Mutex::new(HashSet::new())),
            proxy: None,
        }
    }

    pub fn set_proxy(&mut self, proxy: Socks5Proxy) {
        self.proxy = Some(proxy);
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
            let fatal = self.fatal.clone();
            let proxy = self.proxy.clone();

            let handle = thread::spawn(move || {
                info!(target: Category::NET, "Peer thread {} started", i);
                let mut empty_selections = 0u32;
                while running.load(Ordering::SeqCst) {
                    let selected = {
                        let table = addrman.lock().unwrap();
                        table.select().map(|record| record.network_addr())
                    };
                    let destination = match selected {
                        Some((AddrV2::Ipv4(ipv4), port)) => {
                            Destination::from_socket_addr(SocketAddr::from((ipv4, port)))
                        }
                        Some((AddrV2::Ipv6(ipv6), port)) => {
                            Destination::from_socket_addr(SocketAddr::from((ipv6, port)))
                        }
                        Some((AddrV2::TorV3(pubkey), port)) if proxy.is_some() => {
                            Destination::new(AddrV2::TorV3(pubkey), port)
                        }
                        Some(_) => continue,
                        None => {
                            empty_selections += 1;
                            if empty_selections >= EMPTY_ADDRESS_BOOK_LIMIT {
                                fatal.trigger(
                                    Category::NET,
                                    format!(
                                        "No peer address available for {EMPTY_ADDRESS_BOOK_LIMIT} seconds. \
                                         DNS seeding likely failed and the network is unreachable."
                                    ),
                                );
                                return;
                            }
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    };
                    empty_selections = 0;

                    {
                        let mut connected = connected_peers.lock().unwrap();
                        if !connected.insert(destination.clone()) {
                            drop(connected);
                            debug!(target: Category::NET, "Peer thread {}: {} already connected", i, destination);
                            thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    }

                    let mut peer = match BitcoinPeer::new(
                        destination.clone(),
                        proxy.clone(),
                        network,
                        &node_state,
                    ) {
                        Ok(peer) => {
                            *writer_slot_thread.lock().unwrap() = Some(peer.writer());
                            peer
                        }
                        Err(e) => {
                            error!(target: Category::NET, "Peer thread {}: could not connect to {}: {}", i, destination, e);
                            connected_peers.lock().unwrap().remove(&destination);
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
                    connected_peers.lock().unwrap().remove(&destination);
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

#[derive(Debug, Clone, PartialEq, Eq, std::hash::Hash)]
pub struct Destination {
    pub addr: AddrV2,
    pub port: u16,
}

impl Destination {
    pub fn new(addr: AddrV2, port: u16) -> Self {
        Self { addr, port }
    }

    pub fn from_socket_addr(socket_addr: SocketAddr) -> Self {
        match socket_addr.ip() {
            IpAddr::V4(ipv4) => Destination {
                addr: AddrV2::Ipv4(ipv4),
                port: socket_addr.port(),
            },
            IpAddr::V6(ipv6) => Destination {
                addr: AddrV2::Ipv6(ipv6),
                port: socket_addr.port(),
            },
        }
    }
}

impl core::fmt::Display for Destination {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.addr {
            AddrV2::Ipv4(ipv4) => write!(f, "{}:{}", ipv4, self.port),
            AddrV2::Ipv6(ipv6) => write!(f, "{}:{}", ipv6, self.port),
            AddrV2::TorV3(torv3) => write!(f, "{}:{}", OnionAddress::from_pubkey(torv3), self.port),
            _ => write!(f, "unreachable address"),
        }
    }
}
