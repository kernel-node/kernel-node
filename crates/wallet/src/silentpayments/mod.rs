mod keys_file;
mod scanning;
mod sending;
mod wallet;
mod wallet_store;

pub use ::silentpayments::receiving::{Label, Receiver};
pub use ::silentpayments::{Network, SilentPaymentAddress};
pub use keys_file::{SilentPaymentKeysFile, SpendKey};
pub use scanning::{scan_transaction, InputData};
pub use sending::{Recipient, SendError};
pub use wallet::{Coin, HistoryEntry, SilentPaymentKeys, SpentBy, Wallet};
pub use wallet_store::{WalletPersistenceError, WalletStore, WalletStoreError};

use bitcoin::secp256k1::{self, PublicKey, SecretKey};

pub fn build_receiver(
    b_scan: &SecretKey,
    b_spend_pub: PublicKey,
    network: Network,
) -> Result<Receiver, ::silentpayments::Error> {
    let secp = secp256k1::Secp256k1::signing_only();
    let scan_pubkey = PublicKey::from_secret_key(&secp, b_scan);
    let change_label = Label::new(*b_scan, 0);
    Receiver::new(0, scan_pubkey, b_spend_pub, change_label, network)
}
