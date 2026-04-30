use std::sync::{mpsc, Arc, Mutex};

use secp256k1::{PublicKey, SecretKey};
use wallet::silentpayments::{build_receiver, Network, SilentPaymentWallet};

use crate::{server_capnp, wallet_capnp};

#[derive(Debug)]
pub struct IpcInterface {
    tx: mpsc::Sender<()>,
}

impl IpcInterface {
    pub fn new(tx: mpsc::Sender<()>) -> Self {
        Self { tx }
    }
}

impl server_capnp::server::Server for IpcInterface {
    async fn echo(
        self: capnp::capability::Rc<Self>,
        params: server_capnp::server::EchoParams,
        mut results: server_capnp::server::EchoResults,
    ) -> Result<(), capnp::Error> {
        let request = params.get()?.get_msg()?;
        let msg = request.to_string()?;
        results.get().set_reply(msg);
        Ok(())
    }

    async fn shutdown(
        self: capnp::capability::Rc<Self>,
        _: server_capnp::server::ShutdownParams,
        _: server_capnp::server::ShutdownResults,
    ) -> Result<(), capnp::Error> {
        self.tx
            .send(())
            .map_err(|_| capnp::Error::failed("could not shutdown server.".to_string()))?;
        Ok(())
    }
}

/// Shared wallet state accessed by both the block-scanning thread and the IPC server.
/// Cloning is cheap — all fields are Arc.
#[derive(Clone)]
pub struct WalletState {
    pub wallet: Arc<Mutex<SilentPaymentWallet>>,
    pub scan_key: Arc<Mutex<Option<SecretKey>>>,
    pub spend_key: Arc<Mutex<Option<PublicKey>>>,
    pub network: Network,
}

impl WalletState {
    pub fn new(network: Network) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(SilentPaymentWallet::new())),
            scan_key: Arc::new(Mutex::new(None)),
            spend_key: Arc::new(Mutex::new(None)),
            network,
        }
    }
}

pub struct WalletIpcInterface {
    state: WalletState,
}

impl WalletIpcInterface {
    pub fn new(state: WalletState) -> Self {
        Self { state }
    }
}

impl wallet_capnp::wallet::Server for WalletIpcInterface {
    async fn import_keys(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::ImportKeysParams,
        mut results: wallet_capnp::wallet::ImportKeysResults,
    ) -> Result<(), capnp::Error> {
        let p = params.get()?;
        let scan_bytes = p.get_scan_key()?;
        let spend_bytes = p.get_spend_key()?;

        let scan_key = SecretKey::from_slice(scan_bytes)
            .map_err(|e| capnp::Error::failed(format!("invalid scan key: {e}")))?;
        let spend_key = PublicKey::from_slice(spend_bytes)
            .map_err(|e| capnp::Error::failed(format!("invalid spend key: {e}")))?;

        // Validate that the keys form a valid Receiver before storing.
        build_receiver(&scan_key, spend_key, self.state.network)
            .map_err(|e| capnp::Error::failed(format!("invalid key pair: {e}")))?;

        *self.state.scan_key.lock().unwrap() = Some(scan_key);
        *self.state.spend_key.lock().unwrap() = Some(spend_key);

        results.get().set_ok(true);
        results.get().set_message("keys imported");
        Ok(())
    }

    async fn get_balance(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::GetBalanceParams,
        mut results: wallet_capnp::wallet::GetBalanceResults,
    ) -> Result<(), capnp::Error> {
        let wallet = self.state.wallet.lock().unwrap();
        let balance = wallet.balance();
        let scan_height = wallet.scan_height;
        let utxo_count = wallet.utxo_count() as u32;
        drop(wallet);

        let mut r = results.get();
        r.set_sats(balance.to_sat());
        r.set_scan_height(scan_height);
        r.set_utxo_count(utxo_count);
        Ok(())
    }

    async fn get_history(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::GetHistoryParams,
        mut results: wallet_capnp::wallet::GetHistoryResults,
    ) -> Result<(), capnp::Error> {
        use wallet::silentpayments::HistoryEntry;
        let wallet = self.state.wallet.lock().unwrap();
        let history = wallet.history();
        drop(wallet);

        let text = history
            .iter()
            .map(|e| match e {
                HistoryEntry::Received {
                    outpoint,
                    value,
                    block_height,
                } => {
                    format!(
                        "recv {}:{} {} sats at {}",
                        outpoint.txid,
                        outpoint.vout,
                        value.to_sat(),
                        block_height
                    )
                }
                HistoryEntry::Spent {
                    outpoint,
                    value,
                    spent_at,
                } => {
                    format!(
                        "spent {}:{} {} sats at {}",
                        outpoint.txid,
                        outpoint.vout,
                        value.to_sat(),
                        spent_at
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        results.get().set_entries(&text);
        Ok(())
    }
}
