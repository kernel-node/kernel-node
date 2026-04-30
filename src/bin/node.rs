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

use bitcoin::consensus::deserialize as btc_deserialize;
use bitcoin::p2p::{
    address::{AddrV2, AddrV2Message},
    ServiceFlags,
};
use bitcoin::{hashes::Hash, BlockHash, Network};
use bitcoinkernel::{
    core::BlockHashExt,
    prelude::{
        BlockSpentOutputsExt, BlockValidationStateExt, CoinExt, ScriptPubkeyExt,
        TransactionSpentOutputsExt, TxOutExt,
    },
    ChainType, ChainstateManager, ChainstateManagerBuilder, Context, ContextBuilder, Log, Logger,
    SynchronizationState, ValidationMode,
};
use kernel_node::{
    daemonize::Daemonize,
    ipc::{IpcInterface, WalletIpcInterface, WalletState},
    kernel_util::{ChainExt, DirnameExt, NetworkExt},
    peer::{BitcoinPeer, NodeState, TipState},
    server_capnp::server,
    wallet_capnp::wallet as wallet_ipc,
};
use log::{debug, error, info, warn};
use p2p::dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS};
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use wallet::silentpayments::{build_receiver, scan_block, InputData, Network as WalletNetwork};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

const DNS_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

const STALE_BLOCK_DURATION: Duration = Duration::from_secs(60 * 20);

configure_me::include_config!();

fn to_wallet_network(network: Network) -> WalletNetwork {
    match network {
        Network::Bitcoin => WalletNetwork::Mainnet,
        Network::Regtest => WalletNetwork::Regtest,
        _ => WalletNetwork::Testnet,
    }
}

fn scan_kernel_block(
    chainman: &ChainstateManager,
    kernel_block: &bitcoinkernel::Block,
    wallet_state: &WalletState,
) {
    let scan_key = match *wallet_state.scan_key.lock().unwrap() {
        Some(k) => k,
        None => return,
    };
    let spend_key = match *wallet_state.spend_key.lock().unwrap() {
        Some(k) => k,
        None => return,
    };

    let receiver = match build_receiver(&scan_key, spend_key, wallet_state.network) {
        Ok(r) => r,
        Err(e) => {
            warn!("build_receiver failed: {e}");
            return;
        }
    };

    let entry = chainman.active_chain().tip();
    let block_height = entry.height() as u32;

    let undo = match chainman.read_spent_outputs(&entry) {
        Ok(u) => u,
        Err(e) => {
            warn!("read_spent_outputs failed at height {block_height}: {e}");
            return;
        }
    };

    let raw = match kernel_block.consensus_encode() {
        Ok(r) => r,
        Err(e) => {
            warn!("consensus_encode failed: {e}");
            return;
        }
    };
    let btc_block: bitcoin::Block = match btc_deserialize(&raw) {
        Ok(b) => b,
        Err(e) => {
            warn!("block deserialize failed: {e}");
            return;
        }
    };

    // undo[i] corresponds to btc_block.txdata[i+1] (coinbase has no undo entry).
    let mut tx_input_data: Vec<Vec<InputData>> = Vec::new();
    for (undo_idx, tx_spent) in undo.iter().enumerate() {
        let btc_tx = match btc_block.txdata.get(undo_idx + 1) {
            Some(t) => t,
            None => break,
        };
        let mut inputs = Vec::new();
        for (input_idx, btc_input) in btc_tx.input.iter().enumerate() {
            if let Ok(coin) = tx_spent.coin(input_idx) {
                inputs.push(InputData {
                    script_sig: btc_input.script_sig.as_bytes().to_vec(),
                    witness: btc_input.witness.iter().map(|item| item.to_vec()).collect(),
                    prevout_script: coin.output().script_pubkey().to_bytes(),
                    txid: btc_input.previous_output.txid.to_string(),
                    vout: btc_input.previous_output.vout,
                });
            }
        }
        tx_input_data.push(inputs);
    }

    let payments = scan_block(&receiver, &scan_key, &btc_block, tx_input_data);
    if payments.is_empty() {
        return;
    }

    let found: Vec<(bitcoin::Txid, usize, bitcoin::Amount)> = payments
        .iter()
        .filter_map(|(txid, payment)| {
            btc_block
                .txdata
                .iter()
                .find(|tx| tx.compute_txid() == *txid)
                .and_then(|tx| tx.output.get(payment.output_index))
                .map(|out| (*txid, payment.output_index, out.value))
        })
        .collect();

    wallet_state
        .wallet
        .lock()
        .unwrap()
        .process_block(&btc_block, block_height, &found);
    info!(
        "Wallet: found {} silent payment(s) at height {}",
        found.len(),
        block_height
    );
}

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
        Network::Testnet => TESTNET3_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Testnet4 => TESTNET4_SEEDS.into_iter().map(format_hostname).collect(),
        Network::Regtest => Vec::new(),
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
    mut node_state: NodeState,
    shutdown_rx: mpsc::Receiver<()>,
    addr_rx: mpsc::Receiver<Vec<AddrV2Message>>,
    block_rx: mpsc::Receiver<bitcoinkernel::Block>,
    wallet_state: WalletState,
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
    let addrman = Arc::new(Mutex::new(table));

    let running = Arc::new(AtomicBool::new(true));
    let running_addr = running.clone();
    let running_peer = running.clone();
    let running_block = running.clone();

    let peer_source = Arc::clone(&addrman);
    let kill = Arc::new(Mutex::new(None));
    let writer = Arc::clone(&kill);
    let stale_block_kill = Arc::clone(&kill);

    let peer_processing_handler = thread::spawn(move || {
        info!("Starting net processing thread.");
        while running_peer.load(Ordering::SeqCst) {
            let addr_lock = peer_source.lock().unwrap();
            let (address, port) = addr_lock.select().unwrap().network_addr();
            let peer = match address {
                AddrV2::Ipv4(ipv4) => BitcoinPeer::new(
                    SocketAddr::V4(SocketAddrV4::new(ipv4, port)),
                    network,
                    &mut node_state,
                ),
                AddrV2::Ipv6(ipv6) => {
                    let socket_adrr = (ipv6, port).into();
                    BitcoinPeer::new(socket_adrr, network, &mut node_state)
                }
                _ => continue,
            };
            let mut peer = match peer {
                Ok(connection) => {
                    let mut writer_lock = writer.lock().unwrap();
                    *writer_lock = Some(connection.writer());
                    connection
                }
                Err(e) => {
                    error!("Could not connect: {e}");
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            loop {
                if let Err(e) = peer.receive_and_process_message(&mut node_state) {
                    match e {
                        p2p::net::Error::Io(io) => {
                            if io.kind() != std::io::ErrorKind::UnexpectedEof {
                                error!("Unexpected I/O error: {}", io);
                            }
                        }
                        e => error!("Error processing message: {e}"),
                    }
                    break;
                }
            }
        }
        info!("Stopping net processing thread.");
    });

    let addr_processing_handler = thread::spawn(move || {
        info!("Starting addr processing thread.");
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
        info!("Stopping addr processing thread.");
    });

    let block_processing_handler = thread::spawn(move || {
        info!("Starting block processing thread.");
        let mut last_block = Instant::now();
        while running_block.load(Ordering::SeqCst) {
            match block_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(block) => {
                    debug!("Validating block.");
                    last_block = Instant::now();
                    let result = chainman.process_block(&block);
                    if result.is_new_block() {
                        scan_kernel_block(&chainman, &block, &wallet_state);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if last_block.elapsed() > STALE_BLOCK_DURATION {
                        last_block = Instant::now();
                        info!("Potential stale block. Finding a new peer.");
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
        info!("Stopping block processing thread.");
    });

    if let Ok(()) = shutdown_rx.recv() {
        context.interrupt().unwrap();
        let mut peer_lock = kill.lock().unwrap();
        if let Some(conn) = peer_lock.deref_mut() {
            conn.shutdown().unwrap()
        }
        info!("Received shutdown signal, shutting down...");
        running.store(false, Ordering::SeqCst);
    }

    addr_processing_handler.join().unwrap();
    peer_processing_handler.join().unwrap();
    block_processing_handler.join().unwrap();

    info!("exiting.");
    Ok(())
}

fn main() {
    let (config, _) = Config::including_optional_config_files::<&[&str]>(&[]).unwrap_or_exit();
    START.call_once(|| {
        setup_logging();
    });
    if config.daemon {
        let daemonize = Daemonize::new(config.datadir.data_dir());
        info!("Kernel node starting...");
        daemonize.fork().unwrap();
    }

    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let ipc_shutdown = shutdown_tx.clone();

    let tip_state = Arc::new(Mutex::new(TipState::default()));

    let network = config.network.parse::<Network>().expect("invalid network");
    let context = create_context(network.chain_type(), shutdown_tx.clone(), &tip_state);

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

    let (block_tx, block_rx) = mpsc::sync_channel(1);
    let (addr_tx, addr_rx) = mpsc::channel();

    let node_state = NodeState {
        addr_tx,
        block_tx,
        tip_state,
        chainman,
        context: Arc::clone(&context),
    };

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

    let wallet_state = WalletState::new(to_wallet_network(network));

    let node_sock_file = data_dir.clone() + "/node.sock";
    let wallet_sock_file = data_dir.clone() + "/wallet.sock";

    let wallet_state_for_ipc = wallet_state.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            tokio::task::LocalSet::new()
                .run_until(async move {
                    let _ = std::fs::remove_file(&node_sock_file);
                    let _ = std::fs::remove_file(&wallet_sock_file);
                    info!("Listening for incoming IPC requests");
                    let node_unix_socket = UnixListener::bind(&node_sock_file).unwrap();
                    let wallet_unix_socket = UnixListener::bind(&wallet_sock_file).unwrap();

                    tokio::task::spawn_local(async move {
                        loop {
                            let stream = wallet_unix_socket.accept().await.unwrap().0;
                            let state = wallet_state_for_ipc.clone();
                            let (reader, writer) = stream.into_split();
                            let buf_reader = futures::io::BufReader::new(reader.compat());
                            let buf_writer = futures::io::BufWriter::new(writer.compat_write());
                            let network = capnp_rpc::twoparty::VatNetwork::new(
                                buf_reader,
                                buf_writer,
                                capnp_rpc::rpc_twoparty_capnp::Side::Server,
                                Default::default(),
                            );
                            let client: wallet_ipc::Client =
                                capnp_rpc::new_client(WalletIpcInterface::new(state));
                            let rpc_system =
                                capnp_rpc::RpcSystem::new(Box::new(network), Some(client.client));
                            tokio::task::spawn_local(rpc_system);
                        }
                    });

                    loop {
                        let stream = tokio::select! {
                            unix_bind_res = node_unix_socket.accept() => {
                                unix_bind_res.unwrap().0
                            }
                            _ctrl_c = tokio::signal::ctrl_c() => {
                                info!("Received shutdown signal");
                                shutdown_tx.clone().send(()).unwrap();
                                return;
                            }
                        };
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
                        let client: server::Client =
                            capnp_rpc::new_client(IpcInterface::new(ipc_shutdown.clone()));
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
        wallet_state,
    )
    .unwrap()
}
