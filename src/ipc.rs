use std::sync::{mpsc, Arc, Mutex};

use bitcoin::consensus::Decodable;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, FeeRate, Transaction};
use wallet::silentpayments::{Recipient, Wallet};

use crate::{server_capnp, wallet_capnp};

#[derive(Debug)]
pub struct IpcInterface {
    tx: mpsc::Sender<()>,
    broadcast_tx: mpsc::SyncSender<Transaction>,
    state: Arc<Mutex<Wallet>>,
}

impl IpcInterface {
    pub fn new(
        tx: mpsc::Sender<()>,
        broadcast_tx: mpsc::SyncSender<Transaction>,
        state: Arc<Mutex<Wallet>>,
    ) -> Self {
        Self {
            tx,
            broadcast_tx,
            state,
        }
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

    async fn make_wallet(
        self: capnp::capability::Rc<Self>,
        _: server_capnp::server::MakeWalletParams,
        mut results: server_capnp::server::MakeWalletResults,
    ) -> Result<(), capnp::Error> {
        let client: wallet_capnp::wallet::Client = capnp_rpc::new_client(WalletIpcInterface::new(
            self.state.clone(),
            self.broadcast_tx.clone(),
        ));
        results.get().set_wallet(client);
        Ok(())
    }
}

pub struct WalletIpcInterface {
    state: Arc<Mutex<Wallet>>,
    broadcast_tx: mpsc::SyncSender<Transaction>,
}

impl WalletIpcInterface {
    pub fn new(state: Arc<Mutex<Wallet>>, broadcast_tx: mpsc::SyncSender<Transaction>) -> Self {
        Self {
            state,
            broadcast_tx,
        }
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
        let spend_xonly = XOnlyPublicKey::from_slice(spend_bytes)
            .map_err(|e| capnp::Error::failed(format!("invalid spend key: {e}")))?;

        let mut wallet = self.state.lock().unwrap();
        wallet
            .import_keys(scan_key, spend_xonly)
            .map_err(|e| capnp::Error::failed(format!("invalid key pair: {e}")))?;

        results.get().set_ok(true);
        results.get().set_message("keys imported");
        Ok(())
    }

    async fn get_balance(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::GetBalanceParams,
        mut results: wallet_capnp::wallet::GetBalanceResults,
    ) -> Result<(), capnp::Error> {
        let wallet = self.state.lock().unwrap();
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
        let wallet = self.state.lock().unwrap();
        let history = wallet.history();
        drop(wallet);

        let text = history
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        results.get().set_entries(&text);
        Ok(())
    }

    async fn receive(
        self: capnp::capability::Rc<Self>,
        _: wallet_capnp::wallet::ReceiveParams,
        mut results: wallet_capnp::wallet::ReceiveResults,
    ) -> Result<(), capnp::Error> {
        let wallet = self.state.lock().unwrap();
        let address = wallet
            .receive_address()
            .ok_or_else(|| capnp::Error::failed("no keys imported".to_string()))?;
        drop(wallet);

        results.get().set_address(&address);
        Ok(())
    }

    async fn broadcast_raw_tx(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::BroadcastRawTxParams,
        mut results: wallet_capnp::wallet::BroadcastRawTxResults,
    ) -> Result<(), capnp::Error> {
        let mut raw = params.get()?.get_tx()?;
        let tx = Transaction::consensus_decode(&mut raw)
            .map_err(|e| capnp::Error::failed(format!("invalid transaction: {e}")))?;
        let txid = tx.compute_txid().to_string();
        self.broadcast_tx
            .try_send(tx)
            .map_err(|e| capnp::Error::failed(format!("broadcast unavailable: {e}")))?;
        results.get().set_txid(&txid);
        Ok(())
    }

    async fn send_to_address(
        self: capnp::capability::Rc<Self>,
        params: wallet_capnp::wallet::SendToAddressParams,
        mut results: wallet_capnp::wallet::SendToAddressResults,
    ) -> Result<(), capnp::Error> {
        let p = params.get()?;
        let address = p.get_address()?.to_string()?;
        let amount = Amount::from_sat(p.get_amount_sat());
        let fee_rate_sat_per_vb = p.get_fee_rate_sat_per_vb();
        if !fee_rate_sat_per_vb.is_finite() || fee_rate_sat_per_vb < 0.0 {
            return Err(capnp::Error::failed(
                "fee rate must be a non-negative number".to_string(),
            ));
        }
        // 250 sat/kwu equals 1 sat/vB, rounded up so the rate is never below what was asked
        let fee_rate = FeeRate::from_sat_per_kwu((fee_rate_sat_per_vb * 250.0).ceil() as u64);
        let mut wallet = self.state.lock().unwrap();
        let recipient = Recipient::parse(&address, wallet.network)
            .map_err(|e| capnp::Error::failed(format!("invalid recipient: {e}")))?;
        let tx = wallet
            .build_transaction(recipient, amount, fee_rate)
            .map_err(|e| capnp::Error::failed(format!("could not build transaction: {e}")))?;
        let outpoints: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();
        let txid = tx.compute_txid().to_string();
        self.broadcast_tx
            .try_send(tx)
            .map_err(|e| capnp::Error::failed(format!("broadcast unavailable: {e}")))?;
        wallet.reserve_coins(outpoints);
        drop(wallet);

        results.get().set_txid(&txid);
        Ok(())
    }
}
