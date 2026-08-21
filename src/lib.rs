use ::bitcoin::Network;
use log::error;
use p2p::dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS};
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

pub mod daemonize;
pub mod ext;
pub mod ipc;
pub mod peer;
pub mod peer_manager;

pub mod logging {
    pub struct Category;

    impl Category {
        pub const KERNEL: &str = "kernel";
        pub const NET: &str = "net";
        pub const WALLET: &str = "wallet";
        pub const IPC: &str = "ipc";
        pub const NODE: &str = "node";
    }
}

pub enum ScanEvent {
    Connected {
        block_height: u32,
        block: bitcoinkernel::Block,
        spent_outputs: bitcoinkernel::BlockSpentOutputs,
    },
    Disconnected {
        block: bitcoinkernel::Block,
        block_height: u32,
    },
}

#[derive(Clone)]
pub struct FatalShutdown {
    triggered: Arc<AtomicBool>,
    tx: mpsc::Sender<()>,
}

impl FatalShutdown {
    pub fn new(tx: mpsc::Sender<()>) -> Self {
        Self {
            triggered: Arc::new(AtomicBool::new(false)),
            tx,
        }
    }

    pub fn trigger(&self, target: &str, message: impl std::fmt::Display) {
        error!(target: target, "{}", message);
        if !self.triggered.swap(true, Ordering::SeqCst) {
            self.tx.send(()).expect("failed to send shutdown signal");
        }
    }
}

pub fn resolve_seeds(network: Network) -> Vec<IpAddr> {
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

capnp::generated_code!(pub mod server_capnp);
capnp::generated_code!(pub mod wallet_capnp);
capnp::generated_code!(pub mod chain_capnp);
