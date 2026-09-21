use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::Network;
use bitcoin_payment_instructions::dns_resolver::DNSHrnResolver;
use bitcoin_payment_instructions::{
    PaymentInstructions, PaymentMethod, PossiblyResolvedPaymentMethod,
};
use clap::Parser;
use kernel_node::ext::DirnameExt;
use kernel_node::server_capnp::server;
use tokio::net::UnixStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use wallet::io::FileExt;
use wallet::silentpayments::{SilentPaymentKeysFile, SpendKey};

const DEFAULT_DATA_DIR: &str = "~/.kernel-node/";

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Clone, clap::Args)]
struct Opts {
    /// Path to the data directory.
    #[arg(long, short)]
    datadir: Option<String>,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Commands {
    /// Echo a message to yourself.
    Echo(Echo),
    /// Terminate the server.
    Stop,
    /// Chain commands.
    #[command(subcommand)]
    Chain(ChainCmd),
    /// Wallet commands.
    #[command(subcommand)]
    Wallet(WalletCmd),
}

#[derive(Debug, Clone, clap::Subcommand)]
enum ChainCmd {
    /// Show the current chain tip.
    Tip,
}

#[derive(Debug, Clone, clap::Args)]
struct Echo {
    /// The message to echo.
    message: String,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum WalletCmd {
    /// Generate fresh scan and spend keys for receiving silent payments.
    ///
    /// By default, prints the scan key, spend private key, and spend
    /// x-only public key as hex on stdout. With `--out <path>`, writes
    /// the secrets to a binary file and prints only the spend public
    /// key on stderr. WARNING: anyone with the scan key and spend
    /// private key can spend received funds.
    GenerateKeys {
        /// Write the keys to this binary file. Must not already exist.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import BIP-352 silent payment keys to enable scanning for incoming payments.
    ///
    /// Both keys are hex-encoded. The scan key derives the ECDH shared secret with
    /// each transaction; the spend pubkey identifies the receiver.
    ImportKeys {
        /// 32-byte scan private key as hex.
        scan_key: String,
        /// 32-byte x-only spend public key as hex.
        spend_key: String,
    },
    /// Print scan_key, spend_priv and spend_pub keys to stdout from file.
    PrintKeysFromKeysFile { path: PathBuf },
    /// Show wallet balance.
    Balance,
    /// Show wallet transaction history.
    History,
    /// Show the silent payment address the wallet is scanning for.
    Receive,
    /// Broadcast a raw transaction to the network.
    BroadcastRawTx {
        /// Hex-encoded raw transaction.
        tx: String,
    },
    /// Send to a silent payment address or a bitcoin address.
    SendToAddress {
        /// The recipient silent payment address or bitcoin address.
        address: String,
        /// Amount to send, in satoshis.
        amount_sat: u64,
        /// Fee rate, in satoshis per virtual byte.
        fee_rate_sat_per_vb: f64,
        /// The maximum feerate in sats/vB at which transaction building may
        /// use more inputs than strictly necessary so that the wallet's UTXO
        /// pool can be reduced (default: 10 sats/vB).  Long term fee rate,
        /// in satoshis per virtual byte.
        ///
        /// Setting the consolidate fee rate helps the coin-selection
        /// algorithm know if to use more UTXOs or less when building a
        /// transaction.  That is, if the current fee rate is high
        /// (fee rate > consolidate fee rate), then consume less inputs making
        /// the transaction cheaper.  Likewise, if the current fee rate is low,
        /// use more inputs and consolidate the UTXO set to be fewer.
        consolidate_fee_rate_sat_per_vb: Option<f64>,
    },
    /// Resolve a BIP 353 human-readable name over DNSSEC and send to the
    /// on-chain or silent payment address it points to.
    PayToDomain {
        /// The BIP 353 human-readable name, in `name@domain` form.
        domain: String,
        /// Amount to send, in satoshis.
        amount_sat: u64,
        /// Fee rate, in satoshis per virtual byte.
        fee_rate_sat_per_vb: f64,
        /// The maximum feerate in sats/vB at which transaction building may
        /// use more inputs than strictly necessary so that the wallet's UTXO
        /// pool can be reduced (default: 10 sats/vB).  Long term fee rate,
        /// in satoshis per virtual byte.
        ///
        /// Setting the consolidate fee rate helps the coin-selection
        /// algorithm know if to use more UTXOs or less when building a
        /// transaction.  That is, if the current fee rate is high
        /// (fee rate > consolidate fee rate), then consume less inputs making
        /// the transaction cheaper.  Likewise, if the current fee rate is low,
        /// use more inputs and consolidate the UTXO set to be fewer.
        consolidate_fee_rate_sat_per_vb: Option<f64>,
        /// The recursive DNS resolver to use for DNSSEC resolution.
        #[arg(long, default_value = "8.8.8.8:53")]
        dns: SocketAddr,
    },
}

fn generate_keys() -> (SecretKey, SecretKey, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let scan_priv = SecretKey::new(&mut OsRng);
    let spend_priv = SecretKey::new(&mut OsRng);
    let (spend_xonly, _) = spend_priv.public_key(&secp).x_only_public_key();
    (scan_priv, spend_priv, spend_xonly)
}

/// Resolves a BIP 353 human-readable name over DNSSEC, returning the first
/// silent payment or on-chain address it contains.
async fn resolve_domain(domain: &str, network: Network, dns: SocketAddr) -> String {
    let resolver = DNSHrnResolver(dns);
    let instructions = PaymentInstructions::parse(domain, network, &resolver, true)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to resolve {domain}: {e:?}");
            std::process::exit(1);
        });

    let methods: Vec<&PaymentMethod> = match &instructions {
        PaymentInstructions::FixedAmount(instr) => instr.methods().iter().collect(),
        PaymentInstructions::ConfigurableAmount(instr) => instr
            .methods()
            .filter_map(|method| match method {
                PossiblyResolvedPaymentMethod::Resolved(payment_method) => Some(payment_method),
                PossiblyResolvedPaymentMethod::LNURLPay { .. } => None,
            })
            .collect(),
    };

    // Prefer silent payments, falling back to a plain on-chain address.
    methods
        .iter()
        .find_map(|method| match method {
            PaymentMethod::SilentPayment(address) => Some(address.to_string()),
            _ => None,
        })
        .or_else(|| {
            methods.iter().find_map(|method| match method {
                PaymentMethod::OnChain(address) => Some(address.to_string()),
                _ => None,
            })
        })
        .unwrap_or_else(|| {
            eprintln!("no on-chain or silent payment instructions found for {domain}");
            std::process::exit(1);
        })
}

async fn connect_server(datadir_path: &str) -> server::Client {
    let sock_file = datadir_path.to_owned() + "/node.sock";
    let stream = UnixStream::connect(&sock_file)
        .await
        .expect("Could not connect to node.sock. Is `node` running?");
    let (reader, writer) = stream.into_split();
    let buf_reader = futures::io::BufReader::new(reader.compat());
    let buf_writer = futures::io::BufWriter::new(writer.compat_write());
    let network = capnp_rpc::twoparty::VatNetwork::new(
        buf_reader,
        buf_writer,
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        Default::default(),
    );
    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);
    let client: server::Client = rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);
    tokio::task::spawn_local(rpc_system);
    client
}

fn main() {
    let cli = Args::parse();

    if let Commands::Wallet(WalletCmd::GenerateKeys { out }) = &cli.commands {
        let (scan_priv, spend_priv, spend_pub) = generate_keys();
        match out {
            Some(path) => {
                let file = SilentPaymentKeysFile::new(scan_priv, SpendKey::Secret(spend_priv));
                file.save(path).expect("failed to write keys file");
                println!("Wrote silent payment keys to {}", path.display());
                println!("spend_pub={}", spend_pub);
            }
            None => {
                eprintln!("WARNING: scan_key and spend_priv must be kept secret — anyone with them can spend received funds.");
                println!("scan_key={}", scan_priv.display_secret());
                println!("spend_priv={}", spend_priv.display_secret());
                println!("spend_pub={}", spend_pub);
            }
        }
        return;
    }

    if let Commands::Wallet(WalletCmd::PrintKeysFromKeysFile { path }) = &cli.commands {
        let read = SilentPaymentKeysFile::load(path)
            .expect("file path provided should be readable as a silent payments keys file");

        let spend_pub = read.spend_xonly();
        eprintln!("spend_pub={}", spend_pub);

        let scan_priv = read.scan_key();
        eprintln!("scan_key={}", scan_priv.display_secret());
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let datadir_path = cli.opts.datadir.unwrap_or(DEFAULT_DATA_DIR.data_dir());

    rt.block_on(tokio::task::LocalSet::new().run_until(async move {
        let client = connect_server(&datadir_path).await;
        match cli.commands {
            Commands::Echo(echo) => {
                let mut echo_req = client.echo_request();
                println!("Sending... {}", echo.message);
                echo_req.get().set_msg(echo.message);
                let result = echo_req.send().promise.await.unwrap();
                let result = result
                    .get()
                    .unwrap()
                    .get_reply()
                    .unwrap()
                    .to_string()
                    .unwrap();
                println!("{result}");
            }
            Commands::Stop => {
                let shutdown_req = client.shutdown_request();
                shutdown_req.send().promise.await.unwrap();
                println!("Kernel node stopping...");
            }
            Commands::Chain(cmd) => {
                let chain_response = client.make_chain_request().send().promise.await.unwrap();
                let client = chain_response.get().unwrap().get_chain().unwrap();
                match cmd {
                    ChainCmd::Tip => {
                        let req = client.get_tip_request();
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let height = r.get_height();
                        let hash = r.get_hash().unwrap().to_string().unwrap();
                        println!("height={height} hash={hash}");
                    }
                }
            }
            Commands::Wallet(cmd) => {
                let wallet_response = client.make_wallet_request().send().promise.await.unwrap();
                let wallet_client = wallet_response.get().unwrap().get_wallet().unwrap();
                match cmd {
                    WalletCmd::GenerateKeys { .. } => unreachable!("handled before runtime"),
                    WalletCmd::PrintKeysFromKeysFile { .. } => {
                        unreachable!("handled before runtime")
                    }
                    WalletCmd::ImportKeys {
                        scan_key,
                        spend_key,
                    } => {
                        let scan_bytes =
                            Vec::<u8>::from_hex(&scan_key).expect("scan_key must be valid hex");
                        let spend_bytes =
                            Vec::<u8>::from_hex(&spend_key).expect("spend_key must be valid hex");

                        let mut req = wallet_client.import_keys_request();
                        req.get().set_scan_key(&scan_bytes);
                        req.get().set_spend_key(&spend_bytes);
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let msg = r.get_message().unwrap().to_string().unwrap();
                        println!("{}", msg);
                    }
                    WalletCmd::Balance => {
                        let req = wallet_client.get_balance_request();
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        println!(
                            "Balance: {} sats | scan height: {} | UTXOs: {}",
                            r.get_sats(),
                            r.get_scan_height(),
                            r.get_utxo_count(),
                        );
                    }
                    WalletCmd::History => {
                        let req = wallet_client.get_history_request();
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let entries = r.get_entries().unwrap().to_string().unwrap();
                        if entries.is_empty() {
                            println!("No history yet.");
                        } else {
                            println!("{}", entries);
                        }
                    }
                    WalletCmd::Receive => {
                        let req = wallet_client.receive_request();
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let address = r.get_address().unwrap().to_string().unwrap();
                        println!("{}", address);
                    }
                    WalletCmd::BroadcastRawTx { tx } => {
                        let raw_bytes = Vec::<u8>::from_hex(&tx).expect("tx must be valid hex");
                        let mut req = wallet_client.broadcast_raw_tx_request();
                        req.get().set_tx(&raw_bytes);
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let txid = r.get_txid().unwrap().to_string().unwrap();
                        println!("{}", txid);
                    }
                    WalletCmd::SendToAddress {
                        address,
                        amount_sat,
                        fee_rate_sat_per_vb,
                        consolidate_fee_rate_sat_per_vb,
                    } => {
                        let mut req = wallet_client.send_to_address_request();
                        req.get().set_address(&address);
                        req.get().set_amount_sat(amount_sat);
                        req.get().set_fee_rate_sat_per_vb(fee_rate_sat_per_vb);

                        if let Some(consolidate_fee_rate) = consolidate_fee_rate_sat_per_vb {
                            req.get()
                                .set_consolidate_fee_rate_sat_per_vb(consolidate_fee_rate);
                        }

                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let message = r.get_message().unwrap().to_string().unwrap();
                        if r.get_ok() {
                            println!("{}", message);
                        } else {
                            eprintln!("{}", message);
                            std::process::exit(1);
                        }
                    }
                    WalletCmd::PayToDomain {
                        domain,
                        amount_sat,
                        fee_rate_sat_per_vb,
                        consolidate_fee_rate_sat_per_vb,
                        dns,
                    } => {
                        let network_response =
                            client.network_request().send().promise.await.unwrap();
                        let network = network_response
                            .get()
                            .unwrap()
                            .get_network()
                            .unwrap()
                            .to_string()
                            .unwrap()
                            .parse::<Network>()
                            .expect("node returned an invalid network");

                        let address = resolve_domain(&domain, network, dns).await;
                        println!("Resolved {domain} to {address}");

                        let mut req = wallet_client.send_to_address_request();
                        req.get().set_address(&address);
                        req.get().set_amount_sat(amount_sat);
                        req.get().set_fee_rate_sat_per_vb(fee_rate_sat_per_vb);

                        if let Some(consolidate_fee_rate) = consolidate_fee_rate_sat_per_vb {
                            req.get()
                                .set_consolidate_fee_rate_sat_per_vb(consolidate_fee_rate);
                        }

                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let message = r.get_message().unwrap().to_string().unwrap();
                        if r.get_ok() {
                            println!("{}", message);
                        } else {
                            eprintln!("{}", message);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }))
}
