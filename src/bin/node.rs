use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex, Once,
    },
    thread::{self, available_parallelism},
    time::{Duration, Instant},
};

use bitcoin::p2p::{
    address::{AddrV2, AddrV2Message},
    message::NetworkMessage,
    ServiceFlags,
};
use bitcoin::{hashes::Hash, BlockHash, Network, Transaction};
use bitcoinkernel::{
    core::BlockHashExt, prelude::BlockValidationStateExt, ChainType, ChainstateManager,
    ChainstateManagerBuilder, Context, ContextBuilder, Log, Logger, SynchronizationState,
    ValidationMode,
};
use kernel_node::{
    daemonize::Daemonize,
    ext::{ChainExt, DirnameExt, NetworkExt},
    ipc::IpcInterface,
    logging::Category,
    peer::{BitcoinPeer, NodeState, TipState},
    resolve_seeds,
    server_capnp::server,
    FatalShutdown, ScanEvent,
};
use log::{debug, error, info, warn};
use p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, TimeoutParams},
};
use std::path::PathBuf;
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use wallet::io::FileExt;
use wallet::silentpayments::{SilentPaymentKeysFile, SpendKey, Wallet, WalletStore};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

const DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

const STALE_BLOCK_DURATION: Duration = Duration::from_secs(60 * 20);

const BROADCAST_TIMEOUT: Duration = Duration::from_secs(60);

configure_me::include_config!();

fn create_context(
    chain_type: ChainType,
    fatal: FatalShutdown,
    tip_state: &Arc<Mutex<TipState>>,
    wallet: Arc<Mutex<Wallet>>,
    chainman_holder: Arc<std::sync::OnceLock<Arc<ChainstateManager>>>,
    scan_tx: mpsc::Sender<ScanEvent>,
) -> Arc<Context> {
    let tip_state_clone = tip_state.clone();
    let scan_tx_disconnect = scan_tx.clone();
    let fatal_connected = fatal.clone();
    let fatal_disconnected = fatal.clone();
    let fatal_flush = fatal.clone();
    Arc::new(ContextBuilder::new()
        .chain_type(chain_type)
        .with_block_connected_validation(move |block: bitcoinkernel::Block, entry: bitcoinkernel::BlockTreeEntry<'_>| {
            if wallet.lock().unwrap().keys.is_none() {
                return;
            }
            let Some(chainman) = chainman_holder.get() else { return };
            match chainman.read_spent_outputs(&entry) {
                Ok(spent_outputs) => {
                    if scan_tx.send(ScanEvent::Connected {
                        block_height: entry.height() as u32,
                        block,
                        spent_outputs,
                    }).is_err() {
                        fatal_connected.trigger(Category::NODE, "Scan channel closed unexpectedly during block connection");
                    }
                }
                Err(message) => {
                    fatal_connected.trigger(Category::KERNEL, format!("Fatal error reading block spent outputs: {}", message));
                }
            }
        })
        .with_block_disconnected_validation(move |block: bitcoinkernel::Block, entry: bitcoinkernel::BlockTreeEntry<'_>| {
            if scan_tx_disconnect.send(ScanEvent::Disconnected {
                block,
                block_height: entry.height() as u32,
            }).is_err() {
                fatal_disconnected.trigger(Category::NODE, "Scan channel closed unexpectedly during block disconnection");
            }
        })
        .with_block_tip_notification(|state, hash: bitcoinkernel::BlockHash, _| {
                let hash = BlockHash::from_byte_array(hash.into());
                match state {
                    SynchronizationState::InitDownload => debug!(target: Category::KERNEL, "Received new block tip {} during IBD.", hash),
                    SynchronizationState::PostInit => debug!(target: Category::KERNEL, "Received new block {}", hash),
                    SynchronizationState::InitReindex => debug!(target: Category::KERNEL, "Moved new block tip {} during reindex.", hash),
                };
        })
        .with_header_tip_notification(|state, height, timestamp, presync| {
                match state {
                    SynchronizationState::InitDownload => debug!(target: Category::KERNEL, "Received new header tip during IBD at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::PostInit => info!(target: Category::KERNEL, "Received new header tip at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::InitReindex => debug!(target: Category::KERNEL, "Moved to new header tip during reindex at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                }
        })
        .with_progress_notification(|title, progress, resume_possible| {
                warn!(target: Category::KERNEL, "Made progress {}: {}. Can resume: {}", title, progress, resume_possible)
        })
        .with_warning_set_notification(|_warning, _message| {})
        .with_warning_unset_notification(|_warning| {})
        .with_flush_error_notification(move |message| {
                fatal_flush.trigger(Category::KERNEL, format!("Fatal flush error encountered: {}", message));
        })
        .with_fatal_error_notification(move |message| {
                fatal.trigger(Category::KERNEL, format!("Fatal error encountered: {}", message));
        })
        // .with_block_checked_validation(setup_validation_interface(tip_state))
        .with_block_checked_validation(move |block: bitcoinkernel::Block, state: bitcoinkernel::BlockValidationStateRef<'_>| {
            match state.mode() {
                ValidationMode::Valid => {
                    let hash = bitcoin::BlockHash::from_byte_array(block.hash().into());
                    log::debug!(target: Category::KERNEL, "Validation interface: Successfully checked block: {}", hash);
                    tip_state_clone.lock().unwrap().block_hash = hash;
                }
                _ => error!(target: Category::KERNEL, "Received an invalid block!"),
            }
        })
        .build()
        .unwrap())
}

struct KernelLog {}

impl Log for KernelLog {
    fn log(&self, message: &str) {
        log::info!(
            target: Category::KERNEL,
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    }
}

static START: Once = Once::new();
static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

fn setup_logging() {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    builder.init();

    unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(KernelLog {}).unwrap()) };
}

fn open_feeler(table: &mut addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>, network: Network) {
    if let Some(record) = table.select() {
        let (addr, port) = record.network_addr();
        let socket_addr = match addr {
            AddrV2::Ipv6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), port),
            AddrV2::Ipv4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), port),
            _ => return,
        };
        let conf = ConnectionConfig::new()
            .change_network(network)
            .set_service_requirement(ServiceFlags::NETWORK)
            .offer_services(ServiceFlags::WITNESS)
            .user_agent("/kernel-node:0.1.0/".into());
        match conf.open_connection(socket_addr, TimeoutParams::new()) {
            Ok(_) => {
                info!(target: Category::NODE, "Successful feeler connection opened to {:?}", socket_addr);
                table.successful_connection(&record);
            }
            Err(_) => {
                info!(target: Category::NODE, "Failed feeler connection to {:?}", socket_addr);
                table.failed_connection(&record);
            }
        }
    }
}

fn broadcast_transaction(
    table: &mut addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>,
    network: Network,
    tx: &Transaction,
) -> bool {
    let start = Instant::now();
    loop {
        if start.elapsed() >= BROADCAST_TIMEOUT {
            warn!(target: Category::NODE, "Timed out attempting to broadcast transaction");
            return false;
        }
        let Some(record) = table.select() else {
            return false;
        };
        let (addr, port) = record.network_addr();
        let socket_addr = match addr {
            AddrV2::Ipv6(ipv6) => SocketAddr::new(IpAddr::V6(ipv6), port),
            AddrV2::Ipv4(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), port),
            _ => continue,
        };
        let conf = ConnectionConfig::new()
            .change_network(network)
            .offer_services(ServiceFlags::WITNESS)
            .user_agent("/kernel-node:0.1.0/".into());
        match conf.open_connection(socket_addr, TimeoutParams::new()) {
            Ok((writer, _, _)) => match writer.send_message(NetworkMessage::Tx(tx.clone())) {
                Ok(_) => {
                    info!(target: Category::NODE, "Broadcast transaction to {:?}", socket_addr);
                    table.successful_connection(&record);
                    return true;
                }
                Err(e) => {
                    warn!(target: Category::NODE, "Failed to send transaction to {:?}: {}", socket_addr, e);
                }
            },
            Err(_) => {
                info!(target: Category::NODE, "Failed broadcast connection to {:?}", socket_addr);
                table.failed_connection(&record);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    network: Network,
    connect: Option<SocketAddr>,
    mut node_state: NodeState,
    shutdown_rx: mpsc::Receiver<()>,
    addr_rx: mpsc::Receiver<Vec<AddrV2Message>>,
    block_rx: mpsc::Receiver<bitcoinkernel::Block>,
    scan_rx: mpsc::Receiver<ScanEvent>,
    broadcast_rx: mpsc::Receiver<Transaction>,
    wallet: Arc<Mutex<Wallet>>,
    wallet_store: WalletStore,
    fatal: FatalShutdown,
) -> std::io::Result<()> {
    let mut table = addrman::Table::<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>::new();
    match connect {
        Some(connect) => {
            let record = match connect.ip() {
                IpAddr::V4(ipv4) => addrman::Record::new(
                    AddrV2::Ipv4(ipv4),
                    connect.port(),
                    ServiceFlags::NETWORK,
                    &DNS_RESOLVER,
                ),
                IpAddr::V6(ipv6) => addrman::Record::new(
                    AddrV2::Ipv6(ipv6),
                    connect.port(),
                    ServiceFlags::NETWORK,
                    &DNS_RESOLVER,
                ),
            };
            table.add(&record);
        }
        None => {
            let addresses = resolve_seeds(network);
            info!(target: Category::NET, "Resolved {} addresses from DNS seeds", addresses.len());
            for addr in &addresses {
                let record = match addr {
                    IpAddr::V4(ipv4) => addrman::Record::new(
                        AddrV2::Ipv4(*ipv4),
                        network.default_p2p_port(),
                        ServiceFlags::NETWORK,
                        &DNS_RESOLVER,
                    ),
                    IpAddr::V6(ipv6) => addrman::Record::new(
                        AddrV2::Ipv6(*ipv6),
                        network.default_p2p_port(),
                        ServiceFlags::NETWORK,
                        &DNS_RESOLVER,
                    ),
                };
                table.add(&record);
            }
        }
    };

    let chainman = Arc::clone(&node_state.chainman);
    let context = Arc::clone(&node_state.context);
    let addrman = Arc::new(Mutex::new(table));
    let addrman_for_feelers = Arc::clone(&addrman);
    let wallet_for_broadcast = Arc::clone(&wallet);

    let running = Arc::new(AtomicBool::new(true));
    let running_addr = running.clone();
    let running_peer = running.clone();
    let running_block = running.clone();
    let running_scan = running.clone();
    let running_feelers = running.clone();

    let peer_source = Arc::clone(&addrman);
    let kill = Arc::new(Mutex::new(None));
    let writer = Arc::clone(&kill);
    let stale_block_kill = Arc::clone(&kill);

    let peer_processing_handler = thread::spawn(move || {
        info!(target: Category::NODE, "Starting net processing thread.");
        while running_peer.load(Ordering::SeqCst) {
            let socket_addr = {
                let addr_lock = peer_source.lock().unwrap();
                let (address, port) = addr_lock.select().unwrap().network_addr();
                match address {
                    AddrV2::Ipv4(ipv4) => Some(SocketAddr::V4(SocketAddrV4::new(ipv4, port))),
                    AddrV2::Ipv6(ipv6) => Some(SocketAddr::from((ipv6, port))),
                    _ => None,
                }
            };
            let Some(socket_addr) = socket_addr else {
                continue;
            };
            let peer = BitcoinPeer::new(socket_addr, network, &mut node_state);
            let mut peer = match peer {
                Ok(connection) => {
                    let mut writer_lock = writer.lock().unwrap();
                    *writer_lock = Some(connection.writer());
                    connection
                }
                Err(e) => {
                    error!(target: Category::NET, "Could not connect: {e}");
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            loop {
                if let Err(e) = peer.receive_and_process_message(&mut node_state) {
                    match e {
                        p2p::net::Error::Io(io) => {
                            if io.kind() != std::io::ErrorKind::UnexpectedEof {
                                error!(target: Category::NET, "Unexpected I/O error: {}", io);
                            }
                        }
                        e => error!(target: Category::NET, "Error processing message: {e}"),
                    }
                    break;
                }
            }
        }
        info!(target: Category::NODE, "Stopping net processing thread.");
    });

    let addr_processing_handler = thread::spawn(move || {
        info!(target: Category::NODE, "Starting addr processing thread.");
        while running_addr.load(Ordering::SeqCst) {
            match addr_rx.recv() {
                Ok(payload) => {
                    let mut addr_lock = addrman.lock().unwrap();
                    for address in payload {
                        let record = addrman::Record::new(
                            address.addr,
                            address.port,
                            address.services,
                            &DNS_RESOLVER,
                        );
                        addr_lock.add(&record);
                    }
                }
                Err(_) => break,
            }
        }
        info!(target: Category::NODE, "Stopping addr processing thread.");
    });

    let block_processing_handler = thread::spawn(move || {
        info!(target: Category::NODE, "Starting block processing thread.");
        let mut last_block = Instant::now();
        while running_block.load(Ordering::SeqCst) {
            match block_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(block) => {
                    debug!(target: Category::KERNEL, "Validating block.");
                    last_block = Instant::now();
                    let _ = chainman.process_block(&block);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if last_block.elapsed() > STALE_BLOCK_DURATION {
                        last_block = Instant::now();
                        info!(target: Category::NET, "Potential stale block. Finding a new peer.");
                        let mut peer_lock = stale_block_kill.lock().unwrap();
                        if let Some(conn) = peer_lock.deref_mut() {
                            let _ = conn.shutdown();
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        info!(target: Category::NODE, "Stopping block processing thread.");
    });

    let fatal_scan = fatal.clone();
    let scan_processing_handler = thread::spawn(move || {
        info!(target: Category::NODE, "Starting scan thread.");
        while running_scan.load(Ordering::SeqCst) {
            match scan_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(ScanEvent::Connected {
                    block_height,
                    block,
                    spent_outputs,
                }) => {
                    let mut wallet = wallet.lock().unwrap();
                    let count = wallet.scan_block(block, spent_outputs, block_height);
                    if let Err(e) = wallet_store.save(&wallet) {
                        fatal_scan.trigger(
                            Category::WALLET,
                            format!("Wallet save failed at height {block_height}: {e}"),
                        );
                    }
                    drop(wallet);
                    if count > 0 {
                        info!(
                            target: Category::WALLET,
                            "Found {} silent payment(s) at height {}",
                            count, block_height
                        );
                    }
                }
                Ok(ScanEvent::Disconnected {
                    block,
                    block_height,
                }) => {
                    let mut wallet = wallet.lock().unwrap();
                    wallet.process_disconnect(block);
                    if let Err(e) = wallet_store.save(&wallet) {
                        fatal_scan.trigger(
                            Category::WALLET,
                            format!("Wallet save failed at disconnect of {block_height}: {e}"),
                        );
                    }
                    drop(wallet);
                    info!(target: Category::WALLET, "Disconnected block at height {}", block_height);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        info!(target: Category::NODE, "Stopping scan thread.");
    });

    let feeler_thread = std::thread::spawn(move || {
        info!(target: Category::NODE, "Starting feeler thread.");
        while running_feelers.load(Ordering::SeqCst) {
            match broadcast_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(tx) => {
                    let delivered = {
                        let mut table = addrman_for_feelers.lock().unwrap();
                        broadcast_transaction(table.deref_mut(), network, &tx)
                    };
                    if !delivered {
                        warn!(
                            target: Category::NODE,
                            "Releasing reserved coins after failed broadcast of {}",
                            tx.compute_txid()
                        );
                        wallet_for_broadcast
                            .lock()
                            .unwrap()
                            .release_coins(tx.input.iter().map(|i| i.previous_output));
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    let mut table = addrman_for_feelers.lock().unwrap();
                    open_feeler(table.deref_mut(), network);
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    if let Ok(()) = shutdown_rx.recv() {
        context.interrupt().unwrap();
        let mut peer_lock = kill.lock().unwrap();
        if let Some(conn) = peer_lock.deref_mut() {
            conn.shutdown().unwrap()
        }
        info!(target: Category::NODE, "Received shutdown signal, shutting down...");
        running.store(false, Ordering::SeqCst);
    }

    addr_processing_handler.join().unwrap();
    peer_processing_handler.join().unwrap();
    block_processing_handler.join().unwrap();
    scan_processing_handler.join().unwrap();
    feeler_thread.join().unwrap();

    info!(target: Category::NODE, "Exiting.");
    Ok(())
}

fn auto_import_keys(wallet: &mut Wallet, path: &str) {
    let file = SilentPaymentKeysFile::load(std::path::Path::new(path))
        .unwrap_or_else(|e| panic!("Failed to load silent payment keys from {path}: {e}"));
    let result = match file.spend {
        SpendKey::Secret(spend_secret) => wallet.import_signing_keys(file.scan_key, spend_secret),
        SpendKey::XOnlyPublic(spend_xonly) => wallet.import_keys(file.scan_key, spend_xonly),
    };
    result.unwrap_or_else(|e| panic!("Failed to build silent payment receiver from {path}: {e}"));
    info!(
        target: Category::NODE,
        "Imported silent payment keys from {path}"
    );
}

fn main() {
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    START.call_once(|| {
        setup_logging();
    });
    if config.daemon {
        let daemonize = Daemonize::new(config.datadir.data_dir());
        info!(target: Category::NODE, "Kernel node starting...");
        daemonize.fork().unwrap();
    }

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let ipc_shutdown = shutdown_tx.clone();

    let tip_state = Arc::new(Mutex::new(TipState::default()));

    let network = config.network.parse::<Network>().expect("invalid network");
    let wallet_store = WalletStore::new(
        PathBuf::from(config.datadir.data_dir()).join("wallet.bin"),
        network.wallet_network(),
    );
    let initial_wallet = if wallet_store.exists() {
        match wallet_store.load() {
            Ok(loaded) => {
                info!(
                    target: Category::WALLET,
                    "Loaded wallet from {} (scan_height={})",
                    wallet_store.path().display(),
                    loaded.scan_height
                );
                loaded
            }
            Err(e) => {
                error!(
                    target: Category::WALLET,
                    "Failed to load wallet at {}: {e}",
                    wallet_store.path().display()
                );
                std::process::exit(1);
            }
        }
    } else {
        Wallet::new(wallet_store.network())
    };
    let wallet = Arc::new(Mutex::new(initial_wallet));
    if let Some(path) = config.sp_keys_file.as_ref() {
        auto_import_keys(&mut wallet.lock().unwrap(), path);
    }
    let chainman_holder: Arc<std::sync::OnceLock<Arc<ChainstateManager>>> =
        Arc::new(std::sync::OnceLock::new());

    let (scan_tx, scan_rx) = mpsc::channel::<ScanEvent>();

    let fatal = FatalShutdown::new(shutdown_tx.clone());
    let context = create_context(
        network.chain_type(),
        fatal.clone(),
        &tip_state,
        Arc::clone(&wallet),
        Arc::clone(&chainman_holder),
        scan_tx,
    );

    let data_dir = config.datadir.data_dir();
    let blocks_dir = data_dir.clone() + "/blocks";
    let chainman_builder = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
        .unwrap()
        .worker_threads(
            ((available_parallelism().unwrap().get() / 2) + 1)
                .try_into()
                .unwrap(),
        );
    let chainman = Arc::new(chainman_builder.build().unwrap());
    chainman_holder
        .set(Arc::clone(&chainman))
        .ok()
        .expect("chainman holder already set");

    let (block_tx, block_rx) = mpsc::sync_channel(1);
    let (addr_tx, addr_rx) = mpsc::channel();
    let (broadcast_tx, broadcast_rx) = mpsc::sync_channel::<Transaction>(1);

    let node_state = NodeState {
        addr_tx,
        block_tx,
        tip_state,
        chainman,
        context: Arc::clone(&context),
    };

    if let Err(err) = node_state.chainman.import_blocks() {
        error!(target: Category::KERNEL, "Error importing blocks: {}", err);
        return;
    }

    let tip_index = node_state.chainman.active_chain().tip();
    let hash = tip_index.block_hash();
    node_state.set_tip_state(BlockHash::from_byte_array(hash.to_bytes()));

    info!(target: Category::KERNEL, "Bitcoin kernel initialized");

    let connect = config
        .connect
        .map(|sock| sock.parse::<SocketAddr>().unwrap());

    if shutdown_rx.try_recv().is_ok() {
        info!(target: Category::NODE, "Shutting down!");
        return;
    }

    let wallet_for_ipc = Arc::clone(&wallet);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            tokio::task::LocalSet::new()
                .run_until(async move {
                    let sock_file = data_dir + "/node.sock";
                    let _ = std::fs::remove_file(&sock_file);
                    debug!(target: Category::IPC, "Listening for incoming IPC requests");
                    let unix_socket = UnixListener::bind(sock_file).unwrap();
                    loop {
                        let stream = tokio::select! {
                            unix_bind_res = unix_socket.accept() => {
                                unix_bind_res.unwrap().0
                            }
                            _ctrl_c = tokio::signal::ctrl_c() => {
                                info!(target: Category::NODE, "Received shutdown signal");
                                shutdown_tx.clone().send(()).unwrap();
                                return;
                            }
                        };
                        debug!(target: Category::IPC, "Handling inbound IPC call");
                        let state = Arc::clone(&wallet_for_ipc);
                        let (reader, writer) = stream.into_split();
                        let buf_reader = futures::io::BufReader::new(reader.compat());
                        let buf_writer = futures::io::BufWriter::new(writer.compat_write());
                        let network = capnp_rpc::twoparty::VatNetwork::new(
                            buf_reader,
                            buf_writer,
                            capnp_rpc::rpc_twoparty_capnp::Side::Server,
                            Default::default(),
                        );
                        let client: server::Client = capnp_rpc::new_client(IpcInterface::new(
                            ipc_shutdown.clone(),
                            broadcast_tx.clone(),
                            state,
                        ));
                        let rpc_system =
                            capnp_rpc::RpcSystem::new(Box::new(network), Some(client.client));
                        tokio::task::spawn_local(rpc_system);
                    }
                })
                .await;
        })
    });

    run(
        network,
        connect,
        node_state,
        shutdown_rx,
        addr_rx,
        block_rx,
        scan_rx,
        broadcast_rx,
        wallet,
        wallet_store,
        fatal,
    )
    .unwrap();
}
