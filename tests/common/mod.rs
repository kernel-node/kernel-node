#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute::LockTime, key::TweakedPublicKey, transaction::Version, Address, Amount,
    CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use corepc_node::{Conf, Node, P2P};
use kernel_node::server_capnp::server;
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::sending::calculate_partial_secret;
use silentpayments::SilentPaymentCode;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use wallet::io::FileExt;
use wallet::silentpayments::{SilentPaymentKeysFile, SpendKey};

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const TIP_POLL_INTERVAL: Duration = Duration::from_millis(200);

const CLOSED_PEER: &str = "127.0.0.1:1";

pub fn start_mirror(peer: &Node) -> Node {
    let exe = corepc_node::exe_path().expect("resolve bitcoind");
    let mut conf = Conf::default();
    conf.p2p = P2P::Connect(peer.params.p2p_socket.expect("p2p socket"), true);
    Node::with_conf(exe, &conf).unwrap()
}

pub fn wait_for_height(node: &Node, height: u64, timeout: Duration) -> bitcoin::BlockHash {
    let deadline = Instant::now() + timeout;
    loop {
        let at = node.client.get_block_count().expect("block count").0;
        if at == height {
            return node.client.best_block_hash().expect("best block hash");
        }
        assert!(
            Instant::now() < deadline,
            "peer did not reach height {height} within {timeout:?} (at {at})"
        );
        std::thread::sleep(TIP_POLL_INTERVAL);
    }
}

pub fn peer_addrs(nodes: [&Node; 2]) -> [String; 2] {
    nodes.map(|node| node.params.p2p_socket.expect("p2p socket").to_string())
}

pub fn start_bitcoind() -> Node {
    let exe = corepc_node::exe_path()
        .expect("resolve bitcoind: downloaded build, or BITCOIND_EXE, or bitcoind on PATH");
    let mut conf = Conf::default();
    conf.p2p = P2P::Yes;
    Node::with_conf(exe, &conf).unwrap()
}

pub fn random_signing_keys() -> SilentPaymentKeysFile {
    let mut rng = bitcoin::secp256k1::rand::rngs::OsRng;
    let scan = SecretKey::new(&mut rng);
    let spend = SecretKey::new(&mut rng);
    SilentPaymentKeysFile::new(scan, SpendKey::Secret(spend))
}

async fn connect(socket_path: &Path) -> server::Client {
    let stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
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

pub struct TestNode {
    process: Child,
    datadir: PathBuf,
    _tempdir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
}

impl TestNode {
    pub fn start() -> Self {
        Self::start_connected(CLOSED_PEER, None)
    }

    pub fn start_connected(
        peer: impl std::fmt::Display,
        keys: Option<SilentPaymentKeysFile>,
    ) -> Self {
        Self::start_connected_to(&[peer.to_string()], keys)
    }

    pub fn start_connected_to(peers: &[String], keys: Option<SilentPaymentKeysFile>) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let datadir = tempdir.path().canonicalize().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_node"));
        command
            .arg("--network")
            .arg("regtest")
            .arg("--datadir")
            .arg(&datadir)
            .args(peers.iter().flat_map(|peer| ["--connect", peer]));
        // With no keys, the node starts without a wallet.
        if let Some(keys) = keys {
            let keys_path = datadir.join("keys.bin");
            keys.save(&keys_path).unwrap();
            command.arg("--sp-keys-file").arg(&keys_path);
        }
        let process = command.spawn().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let node = Self {
            process,
            datadir,
            _tempdir: tempdir,
            rt,
        };
        node.wait_until_ready();
        node
    }

    pub fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("--datadir")
            .arg(&self.datadir)
            .args(args)
            .output()
            .unwrap()
    }

    pub fn tip(&self) -> (u32, bitcoin::BlockHash) {
        let socket = self.socket_path();
        self.rt
            .block_on(tokio::task::LocalSet::new().run_until(async move {
                let client = connect(&socket).await;
                let chain = client
                    .make_chain_request()
                    .send()
                    .promise
                    .await
                    .unwrap()
                    .get()
                    .unwrap()
                    .get_chain()
                    .unwrap();
                let response = chain.get_tip_request().send().promise.await.unwrap();
                let reply = response.get().unwrap();
                let height = reply.get_height();
                let hash = reply
                    .get_hash()
                    .unwrap()
                    .to_string()
                    .unwrap()
                    .parse::<bitcoin::BlockHash>()
                    .unwrap();
                (height, hash)
            }))
    }

    pub fn wait_for_tip(&self, height: u64, hash: bitcoin::BlockHash, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let (h, block_hash) = self.tip();
            if u64::from(h) == height && block_hash == hash {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "node did not reach tip {height} within {timeout:?} (node at {h})"
            );
            std::thread::sleep(TIP_POLL_INTERVAL);
        }
    }

    pub fn import_keys(&self, scan_key_hex: &str, spend_pub_hex: &str) {
        let out = self.cli(&["wallet", "import-keys", scan_key_hex, spend_pub_hex]);
        assert!(
            out.status.success(),
            "import-keys failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn receive_address(&self) -> String {
        let socket = self.socket_path();
        self.rt
            .block_on(tokio::task::LocalSet::new().run_until(async move {
                let client = connect(&socket).await;
                let wallet = client
                    .make_wallet_request()
                    .send()
                    .promise
                    .await
                    .unwrap()
                    .get()
                    .unwrap()
                    .get_wallet()
                    .unwrap();
                let response = wallet.receive_request().send().promise.await.unwrap();
                response
                    .get()
                    .unwrap()
                    .get_address()
                    .unwrap()
                    .to_string()
                    .unwrap()
            }))
    }

    pub fn balance(&self) -> Amount {
        let socket = self.socket_path();
        self.rt
            .block_on(tokio::task::LocalSet::new().run_until(async move {
                let client = connect(&socket).await;
                let wallet = client
                    .make_wallet_request()
                    .send()
                    .promise
                    .await
                    .unwrap()
                    .get()
                    .unwrap()
                    .get_wallet()
                    .unwrap();
                let response = wallet.get_balance_request().send().promise.await.unwrap();
                Amount::from_sat(response.get().unwrap().get_sats())
            }))
    }

    pub fn wait_for_balance(&self, min: Amount, timeout: Duration) -> Amount {
        let deadline = Instant::now() + timeout;
        loop {
            let balance = self.balance();
            if balance >= min {
                return balance;
            }
            assert!(
                Instant::now() < deadline,
                "balance did not reach {min} within {timeout:?} (at {balance})"
            );
            std::thread::sleep(TIP_POLL_INTERVAL);
        }
    }

    pub fn wait_for_balance_of(&self, expected: Amount, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let balance = self.balance();
            if balance == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "balance did not settle at {expected} within {timeout:?} (at {balance})"
            );
            std::thread::sleep(TIP_POLL_INTERVAL);
        }
    }

    pub fn stop(mut self) {
        let out = self.cli(&["stop"]);
        assert!(
            out.status.success(),
            "cli stop failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if self.process.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not exit within {STOP_TIMEOUT:?} after stop");
    }

    fn socket_path(&self) -> PathBuf {
        self.datadir.join("node.sock")
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if Path::new(&self.socket_path()).exists() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        panic!("node did not create control socket within {READY_TIMEOUT:?}");
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

pub fn wait_for_core_mempool(core: &Node, txid: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mempool = core.client.get_raw_mempool().unwrap();
        if mempool.0.iter().any(|entry| entry == txid) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Core did not accept {txid} within {timeout:?}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

// Core cannot send to a silent payment address, so build the BIP-352 payment
// here, broadcast it through Core, and mine it.
pub fn fund_silent_payment(core: &Node, sp_address: &str, amount: Amount) -> Txid {
    let secp = Secp256k1::new();

    let sender_sk = SecretKey::from_slice(&[0x21; 32]).unwrap();
    let sender_pk = CompressedPublicKey(sender_sk.public_key(&secp));
    let sender_address = Address::p2wpkh(&sender_pk, Network::Regtest);

    // 101 blocks so the first coinbase is mature.
    core.client
        .generate_to_address(101, &sender_address)
        .unwrap();
    let block1_hash: bitcoin::BlockHash = core.client.get_block_hash(1).unwrap().0.parse().unwrap();
    let coinbase = core
        .client
        .get_block(block1_hash)
        .unwrap()
        .txdata
        .into_iter()
        .next()
        .unwrap();
    let prevout = OutPoint {
        txid: coinbase.compute_txid(),
        vout: 0,
    };
    let prev_txout = coinbase.output[0].clone();

    let sp = SilentPaymentCode::try_from(sp_address).unwrap();
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&prevout.txid.to_byte_array());
    buf[32..].copy_from_slice(&prevout.vout.to_le_bytes());
    let partial_secret = calculate_partial_secret(
        &[(sender_sk, false)],
        &[silentpayments::utils::OutPoint::from_bytes(buf)],
    )
    .unwrap();
    let derived = generate_recipient_pubkeys(vec![sp.into()], partial_secret).unwrap();
    let output_key = derived
        .get(&sp.into())
        .and_then(|keys| keys.first())
        .copied()
        .unwrap();
    let recipient_script =
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key));

    let fee = Amount::from_sat(1_000);
    let change = prev_txout.value - amount - fee;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: amount,
                script_pubkey: recipient_script,
            },
            TxOut {
                value: change,
                script_pubkey: sender_address.script_pubkey(),
            },
        ],
    };

    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(
            0,
            &prev_txout.script_pubkey,
            prev_txout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sender_sk);
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(sender_pk.to_bytes());
    tx.input[0].witness = witness;

    core.client.send_raw_transaction(&tx).unwrap();
    let miner = core.client.new_address().unwrap();
    core.client.generate_to_address(1, &miner).unwrap();
    tx.compute_txid()
}
