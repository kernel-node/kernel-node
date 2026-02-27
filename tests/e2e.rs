//! End-to-end test: sync blocks from a regtest bitcoind.
//!
//! Requires `bitcoind` and `bitcoin-cli` in PATH.
//! Run with: cargo test --test e2e -- --ignored --nocapture

use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Find a free port for test use. On Linux, `bind(0)` assigns ports
/// from the registered range which works reliably. On macOS, `bind(0)`
/// assigns ephemeral ports (49152+) which can be reclaimed by the OS
/// before bitcoind binds; in that case we probe random registered-range
/// ports (10000–49151) instead.
fn available_port() -> u16 {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    if port < 49152 {
        return port;
    }
    // Ephemeral port assigned — fall back to probing the registered range.
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    Instant::now().hash(&mut hasher);
    let mut port = (hasher.finish() % 39152 + 10000) as u16;
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
        port = if port >= 49151 { 10000 } else { port + 1 };
    }
    panic!("could not find a free port in 10000..49151");
}

use bitcoin::{BlockHash, Network};
use bitcoinkernel::{
    prelude::BlockValidationStateExt, ChainType, ChainstateManagerBuilder,
    ContextBuilder, ValidationMode,
};
use kernel_node::peer::{BitcoinPeer, NodeState, TipState};
use tempfile::TempDir;

const BLOCKS_TO_MINE: u32 = 150;
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

struct BitcoindInstance {
    process: Child,
    datadir: String,
    p2p_port: u16,
    rpc_port: u16,
}

impl BitcoindInstance {
    fn start(datadir: &str) -> Self {
        let p2p_port = available_port();
        let rpc_port = available_port();

        let process = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", datadir),
                &format!("-port={}", p2p_port),
                &format!("-rpcport={}", rpc_port),
                "-server=1",
                "-listen=1",
                "-listenonion=0",
                "-txindex=0",
                "-dnsseed=0",
                "-fixedseeds=0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start bitcoind — is it in PATH?");

        let mut instance = BitcoindInstance {
            process,
            datadir: datadir.to_string(),
            p2p_port,
            rpc_port,
        };
        instance.wait_ready();
        instance
    }

    fn cli(&self, args: &[&str]) -> String {
        let output = Command::new("bitcoin-cli")
            .args([
                "-regtest",
                &format!("-datadir={}", self.datadir),
                &format!("-rpcport={}", self.rpc_port),
            ])
            .args(args)
            .output()
            .expect("failed to run bitcoin-cli");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn wait_ready(&mut self) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(status)) = self.process.try_wait() {
                let mut stderr = String::new();
                if let Some(ref mut s) = self.process.stderr {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stderr);
                }
                panic!("bitcoind exited with {}.\n{}", status, stderr.trim());
            }
            let result = self.cli(&["getblockchaininfo"]);
            if result.contains("\"blocks\"") {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
        panic!("bitcoind did not become ready within 30 seconds");
    }

    fn height(&self) -> i32 {
        self.cli(&["getblockcount"])
            .parse()
            .expect("failed to parse block count")
    }

    fn p2p_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.p2p_port).parse().unwrap()
    }
}

impl Drop for BitcoindInstance {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        let _ = self.process.wait();
    }
}

fn has_bitcoind() -> bool {
    Command::new("bitcoind")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
#[ignore]
fn e2e_sync_regtest_blocks() {
    if !has_bitcoind() {
        eprintln!("SKIPPED: bitcoind not found in PATH");
        return;
    }

    let bitcoind_dir = TempDir::new().expect("failed to create temp dir");
    let bitcoind = BitcoindInstance::start(bitcoind_dir.path().to_str().unwrap());
    eprintln!("bitcoind started on p2p={} rpc={}", bitcoind.p2p_port, bitcoind.rpc_port);

    bitcoind.cli(&["createwallet", "test"]);
    let address = bitcoind.cli(&["getnewaddress"]);
    let n = BLOCKS_TO_MINE.to_string();
    bitcoind.cli(&["generatetoaddress", &n, &address]);
    let target_height = bitcoind.height();
    assert_eq!(target_height, BLOCKS_TO_MINE as i32);
    eprintln!("mined {} blocks", target_height);

    let node_dir = TempDir::new().expect("failed to create temp dir");
    let data_dir = node_dir.path().join("data");
    let blocks_dir = node_dir.path().join("blocks");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&blocks_dir).unwrap();

    let tip_state = Arc::new(Mutex::new(TipState::default()));
    let tip_state_cb = Arc::clone(&tip_state);

    let context = Arc::new(
        ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .with_block_checked_validation(
                move |block: bitcoinkernel::Block,
                      state: bitcoinkernel::BlockValidationStateRef<'_>| {
                    if state.mode() == ValidationMode::Valid {
                        let hash = BlockHash::from_byte_array(block.hash().into());
                        tip_state_cb.lock().unwrap().block_hash = hash;
                    }
                },
            )
            .build()
            .expect("failed to build context"),
    );

    let chainman = Arc::new(
        ChainstateManagerBuilder::new(
            &context,
            data_dir.to_str().unwrap(),
            blocks_dir.to_str().unwrap(),
        )
        .expect("failed to create chainstate manager builder")
        .build()
        .expect("failed to build chainstate manager"),
    );
    chainman.import_blocks().expect("failed to import blocks");

    let (block_tx, block_rx) = mpsc::sync_channel(32);
    let (addr_tx, _addr_rx) = mpsc::channel();

    let mut node_state = NodeState {
        addr_tx,
        block_tx,
        tip_state: Arc::clone(&tip_state),
        context: Arc::clone(&context),
        chainman: Arc::clone(&chainman),
    };

    let mut peer = BitcoinPeer::new(bitcoind.p2p_addr(), Network::Regtest, &mut node_state)
        .expect("failed to connect to bitcoind");
    eprintln!("connected to bitcoind");

    let chainman_block = Arc::clone(&chainman);
    let block_processor = thread::spawn(move || {
        while let Ok(block) = block_rx.recv() {
            chainman_block.process_block(&block);
        }
    });

    let start = Instant::now();
    loop {
        if start.elapsed() > SYNC_TIMEOUT {
            break;
        }
        if let Err(e) = peer.receive_and_process_message(&mut node_state) {
            eprintln!("peer disconnected: {}", e);
            break;
        }
        let height = chainman.active_chain().height();
        if height >= target_height {
            eprintln!("synced to height {}", height);
            break;
        }
    }

    drop(node_state);
    let _ = block_processor.join();

    let final_height = chainman.active_chain().height();

    assert_eq!(
        final_height, target_height,
        "kernel-node should have synced to height {}",
        target_height
    );
}
