use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex, Once,
    },
    thread::{self, available_parallelism},
    time::{Duration, Instant},
};

use bitcoin::{BlockHash, Network, TestnetVersion};
use bitcoinkernel::{
    core::BlockHashExt, prelude::BlockValidationStateExt, ChainType, ChainstateManagerBuilder,
    Context, ContextBuilder, Log, Logger, ProcessBlockResult, SynchronizationState, ValidationMode,
};
use kernel_node::peer::{NodeState, PeerManager, TipState};
use kernel_node::{
    echo_capnp::echo,
    ipc::IpcInterface,
    kernel_util::{ChainExt, DirnameExt},
};
use log::{debug, error, info, warn};
use p2p::{
    dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS},
    p2p_message_types::{address::AddrV2, message::AddrV2Payload, NetworkExt, ServiceFlags},
};
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// Last-resort stall threshold for the block processing pipeline.
///
/// Individual peer stalls are handled at the peer layer by
/// `PEER_STALL_TIMEOUT` (30 s), which disconnects a single non-responsive
/// peer and lets the manager replace it. This longer timeout fires when the
/// *entire* pipeline has been idle — meaning every peer stalled or
/// disconnected simultaneously and no replacement produced a block. When it
/// triggers, all current connections are killed so the manager can open a
/// fresh set of peers.
const STALE_BLOCK_DURATION: Duration = Duration::from_secs(60 * 20);

configure_me::include_config!();

fn create_context(
    chain_type: ChainType,
    shutdown_tx: mpsc::Sender<()>,
    tip_state: &Arc<Mutex<TipState>>,
) -> Arc<Context> {
    let shutdown_triggered = Arc::new(AtomicBool::new(false));
    let shutdown_triggered_clone = Arc::clone(&shutdown_triggered);
    let shutdown_tx_clone = shutdown_tx.clone();
    let tip_state_clone = tip_state.clone();
    Arc::new(ContextBuilder::new()
        .chain_type(chain_type)
        .with_block_tip_notification(|state, hash: bitcoinkernel::BlockHash, _| {
                let hash = BlockHash::from_byte_array(hash.into());
                match state {
                    SynchronizationState::InitDownload => debug!("Received new block tip {} during IBD.", hash),
                    SynchronizationState::PostInit => info!("Received new block {}", hash),
                    SynchronizationState::InitReindex => debug!("Moved new block tip {} during reindex.", hash),
                };
        })
        .with_header_tip_notification(|state, height, timestamp, presync| {
                match state {
                    SynchronizationState::InitDownload => debug!("Received new header tip during IBD at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::PostInit => info!("Received new header tip at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                    SynchronizationState::InitReindex => debug!("Moved to new header tip during reindex at height {} and time {}. Presync mode: {}", height, timestamp, presync),
                }
        })
        .with_progress_notification(|title, progress, resume_possible| {
                warn!("Made progress {}: {}. Can resume: {}", title, progress, resume_possible)
        })
        .with_warning_set_notification(|_warning, _message| {})
        .with_warning_unset_notification(|_warning| {})
        .with_flush_error_notification(move |message| {
                if !shutdown_triggered.swap(true, Ordering::SeqCst) {
                    shutdown_tx.send(()).expect("failed to send shutdown signal");
                }
                error!("Fatal flush error encountered: {}", message);
        })
        .with_fatal_error_notification(move |message| {
                error!("Fatal error encountered: {}", message);
                if !shutdown_triggered_clone.swap(true, Ordering::SeqCst) {
                    shutdown_tx_clone.send(()).expect("failed to send shutdown signal");
                }
        })
        .with_block_checked_validation(move |block: bitcoinkernel::Block, state: bitcoinkernel::BlockValidationStateRef<'_>| {
            match state.mode() {
                ValidationMode::Valid => {
                    let hash = bitcoin::BlockHash::from_byte_array(block.hash().into());
                    log::debug!("Validation interface: Successfully checked block: {}", hash);
                    tip_state_clone.lock().unwrap().block_hash = hash;
                }
                _ => error!("Received an invalid block!"),
            }
        })
        .build()
        .unwrap())
}

struct KernelLog {}

impl Log for KernelLog {
    fn log(&self, message: &str) {
        log::info!(
            target: "bitcoinkernel", 
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

fn resolve_seeds(network: Network) -> Vec<IpAddr> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let format_hostname = |host: &str| format!("{host}:53");
    let seeds: Vec<String> = match network {
        Network::Bitcoin => BITCOIN_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Signet => SIGNET_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Testnet(TestnetVersion::V3) => {
            TESTNET3_SEEDS.into_iter().map(format_hostname).collect()
        }
        Network::Testnet(TestnetVersion::V4) => {
            TESTNET4_SEEDS.into_iter().map(format_hostname).collect()
        }
        Network::Regtest => Vec::new(),
        _ => panic!("unknown network."),
    };
    let mut results = Vec::new();
    for host in seeds {
        let peers = rt.block_on(async move {
            tokio::net::lookup_host(host)
                .await
                .map(|sockets| sockets.map(|socket| socket.ip()).collect())
                .unwrap_or(Vec::new())
        });
        results.extend(peers);
    }
    results
}

fn run(
    network: Network,
    connect: Option<SocketAddr>,
    maxpeers: usize,
    node_state: Arc<NodeState>,
    shutdown_rx: mpsc::Receiver<()>,
    addr_rx: mpsc::Receiver<AddrV2Payload>,
    block_rx: mpsc::Receiver<bitcoinkernel::Block>,
) -> std::io::Result<()> {
    let mut table = addrman::Table::new();
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
            info!("{} addresses resolved from the dns seeds", addresses.len());
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

    let mut peer_manager =
        PeerManager::new(table, Arc::clone(&node_state), network).max_peers(maxpeers);
    let peer_manager_addrman = Arc::clone(peer_manager.addrman());
    let running_block = peer_manager.running();

    let running_addr = Arc::clone(&running_block);
    let addr_processing_handler = thread::spawn(move || {
        info!("Starting addr processing thread.");
        while running_addr.load(Ordering::SeqCst) {
            match addr_rx.recv() {
                Ok(payload) => {
                    let mut addr_lock = peer_manager_addrman.lock().unwrap();
                    for address in payload.0 {
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
        info!("Stopping addr processing thread.");
    });

    let peer_writers = peer_manager.peer_writers().to_vec();
    let node_state_block = Arc::clone(&node_state);
    let block_processing_handler = thread::spawn(move || {
        info!("Starting block processing thread.");
        let mut last_block = Instant::now();
        let mut last_log = Instant::now();
        let mut blocks_since_log: u64 = 0;
        while running_block.load(Ordering::SeqCst) {
            match block_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(block) => {
                    debug!("Validating block.");
                    last_block = Instant::now();
                    match chainman.process_block(&block) {
                        ProcessBlockResult::NewBlock => {}
                        ProcessBlockResult::Duplicate => {
                            debug!("Received duplicate block, skipping.");
                            continue;
                        }
                        ProcessBlockResult::Rejected => {
                            warn!("Block rejected by validation.");
                            continue;
                        }
                    }
                    blocks_since_log += 1;
                    if last_log.elapsed() >= Duration::from_secs(10) {
                        let height = chainman.active_chain().height();
                        let queue_remaining = node_state_block.download_queue.lock().unwrap().len();
                        let in_flight = node_state_block.in_flight_blocks.lock().unwrap().len();
                        info!(
                            "Progress: height={}, validated {} blocks in {:.1}s, queue={}, in_flight={}",
                            height,
                            blocks_since_log,
                            last_log.elapsed().as_secs_f64(),
                            queue_remaining,
                            in_flight,
                        );
                        blocks_since_log = 0;
                        last_log = Instant::now();
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if last_block.elapsed() > STALE_BLOCK_DURATION {
                        last_block = Instant::now();
                        info!("Potential stale block. Disconnecting all peers.");
                        for writer_slot in &peer_writers {
                            let mut w = writer_slot.lock().unwrap();
                            if let Some(conn) = w.deref_mut() {
                                let _ = conn.shutdown();
                            }
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        info!("Stopping block processing thread.");
    });

    peer_manager.start();

    if let Ok(()) = shutdown_rx.recv() {
        context.interrupt().unwrap();
        info!("Received shutdown signal, shutting down...");
        peer_manager.stop();
    }

    addr_processing_handler.join().unwrap();
    block_processing_handler.join().unwrap();
    peer_manager.join();

    info!("exiting.");
    Ok(())
}

fn main() {
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    START.call_once(|| {
        setup_logging();
    });
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let tip_state = Arc::new(Mutex::new(TipState::default()));

    let network = config.network.parse::<Network>().expect("invalid network");
    let context = create_context(network.chain_type(), shutdown_tx.clone(), &tip_state);

    ctrlc::set_handler(move || shutdown_tx.send(()).unwrap()).unwrap();
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

    let (block_tx, block_rx) = mpsc::sync_channel(32);
    let (addr_tx, addr_rx) = mpsc::channel();

    let node_state = Arc::new(NodeState {
        addr_tx,
        block_tx,
        tip_state,
        chainman,
        context: Arc::clone(&context),
        in_flight_blocks: Mutex::new(HashSet::new()),
        download_queue: Mutex::new(VecDeque::new()),
        headers_synced: AtomicBool::new(false),
    });

    if let Err(err) = node_state.chainman.import_blocks() {
        error!("Error importing blocks: {}", err);
        return;
    }

    let tip_index = node_state.chainman.active_chain().tip();
    let hash = tip_index.block_hash();
    node_state.set_tip_state(BlockHash::from_byte_array(hash.to_bytes()));

    info!("Bitcoin kernel initialized");

    let connect = config
        .connect
        .map(|sock| sock.parse::<SocketAddr>().unwrap());

    if shutdown_rx.try_recv().is_ok() {
        info!("Shutting down!");
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            tokio::task::LocalSet::new()
                .run_until(async move {
                    let _ = std::fs::remove_file("./node.sock");
                    info!("Listening for incoming IPC requests");
                    let unix_socket = UnixListener::bind("./node.sock").unwrap();
                    loop {
                        let (stream, _) = unix_socket.accept().await.unwrap();
                        info!("Handling inbound IPC call");
                        let (reader, writer) = stream.into_split();
                        let buf_reader = futures::io::BufReader::new(reader.compat());
                        let buf_writer = futures::io::BufWriter::new(writer.compat_write());
                        let network = capnp_rpc::twoparty::VatNetwork::new(
                            buf_reader,
                            buf_writer,
                            capnp_rpc::rpc_twoparty_capnp::Side::Server,
                            Default::default(),
                        );
                        let client: echo::Client = capnp_rpc::new_client(IpcInterface);
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
        config.maxpeers,
        node_state,
        shutdown_rx,
        addr_rx,
        block_rx,
    )
    .unwrap()
}
