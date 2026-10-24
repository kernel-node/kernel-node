use std::{
    fs::{self, File},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use addrman::io::FileExt;
use bitcoin::p2p::address::AddrV2;
use bitcoin::Network;
use log::{info, warn};
use p2p::dns::{BITCOIN_SEEDS, SIGNET_SEEDS, TESTNET3_SEEDS, TESTNET4_SEEDS};

use crate::{logging::Category, net::socks5::OnionAddress};

const TABLE_WIDTH: usize = 16;
const TABLE_SLOT: usize = 16;
const MAX_BUCKETS: usize = 4;

pub type AddrTable = addrman::Table<TABLE_WIDTH, TABLE_SLOT, MAX_BUCKETS>;

pub trait AddrTableExt {
    fn load(path: &Path) -> Self;

    fn save(&self, path: &Path) -> std::io::Result<()>;
}

impl AddrTableExt for AddrTable {
    fn load(path: &Path) -> Self {
        match File::open(path) {
            Ok(mut file) => match file.read_table() {
                Ok(table) => {
                    info!(target: Category::NET, "Loaded address book from {}", path.display());
                    table
                }
                Err(e) => {
                    warn!(target: Category::NET, "Ignoring unreadable {}: {e}", path.display());
                    AddrTable::new()
                }
            },
            Err(_) => AddrTable::new(),
        }
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_file_name("peers.tmp");
        File::create(&tmp)?.write_table(self)?;
        fs::rename(&tmp, path)
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
