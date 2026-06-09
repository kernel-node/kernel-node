use std::path::PathBuf;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey, XOnlyPublicKey};
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
    /// Wallet commands.
    #[command(subcommand)]
    Wallet(WalletCmd),
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
    },
}

fn generate_keys() -> (SecretKey, SecretKey, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let scan_priv = SecretKey::new(&mut OsRng);
    let spend_priv = SecretKey::new(&mut OsRng);
    let (spend_xonly, _) = spend_priv.public_key(&secp).x_only_public_key();
    (scan_priv, spend_priv, spend_xonly)
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
                eprintln!("Wrote silent payment keys to {}", path.display());
                eprintln!("spend_pub={}", spend_pub);
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
            Commands::Wallet(cmd) => {
                let wallet_response = client.make_wallet_request().send().promise.await.unwrap();
                let client = wallet_response.get().unwrap().get_wallet().unwrap();
                match cmd {
                    WalletCmd::GenerateKeys { .. } => unreachable!("handled before runtime"),
                    WalletCmd::ImportKeys {
                        scan_key,
                        spend_key,
                    } => {
                        let scan_bytes =
                            Vec::<u8>::from_hex(&scan_key).expect("scan_key must be valid hex");
                        let spend_bytes =
                            Vec::<u8>::from_hex(&spend_key).expect("spend_key must be valid hex");

                        let mut req = client.import_keys_request();
                        req.get().set_scan_key(&scan_bytes);
                        req.get().set_spend_key(&spend_bytes);
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let msg = r.get_message().unwrap().to_string().unwrap();
                        println!("{}", msg);
                    }
                    WalletCmd::Balance => {
                        let req = client.get_balance_request();
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
                        let req = client.get_history_request();
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
                        let req = client.receive_request();
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let address = r.get_address().unwrap().to_string().unwrap();
                        println!("{}", address);
                    }
                    WalletCmd::BroadcastRawTx { tx } => {
                        let raw_bytes = Vec::<u8>::from_hex(&tx).expect("tx must be valid hex");
                        let mut req = client.broadcast_raw_tx_request();
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
                    } => {
                        let mut req = client.send_to_address_request();
                        req.get().set_address(&address);
                        req.get().set_amount_sat(amount_sat);
                        req.get().set_fee_rate_sat_per_vb(fee_rate_sat_per_vb);
                        let result = req.send().promise.await.unwrap();
                        let r = result.get().unwrap();
                        let txid = r.get_txid().unwrap().to_string().unwrap();
                        println!("{}", txid);
                    }
                }
            }
        }
    }))
}
