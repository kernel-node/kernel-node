mod scanning;
mod wallet;

pub use ::silentpayments::receiving::Receiver;
pub use ::silentpayments::{Network, SilentPaymentAddress};
pub use scanning::{scan_block, scan_transaction, FoundPayment, InputData};
pub use wallet::{HistoryEntry, OwnedUtxo, SilentPaymentWallet, SpentBy};

use ::silentpayments::receiving::Label;
use secp256k1::{PublicKey, SecretKey};

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
