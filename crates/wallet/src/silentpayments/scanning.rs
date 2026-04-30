use ::silentpayments::{
    receiving::Receiver,
    utils::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input},
};
use bitcoin::{Block, Transaction};
use secp256k1::{SecretKey, XOnlyPublicKey};

pub struct InputData {
    pub script_sig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub prevout_script: Vec<u8>,
    pub txid: String,
    pub vout: u32,
}

pub struct FoundPayment {
    pub output_index: usize,
    pub pubkey: XOnlyPublicKey,
}

pub fn scan_transaction(
    receiver: &Receiver,
    b_scan: &SecretKey,
    inputs: &[InputData],
    tx: &Transaction,
) -> Vec<FoundPayment> {
    let mut input_pub_keys = Vec::new();
    let mut outpoints = Vec::new();
    for input in inputs {
        if let Ok(Some(pk)) =
            get_pubkey_from_input(&input.script_sig, &input.witness, &input.prevout_script)
        {
            input_pub_keys.push(pk);
            outpoints.push((input.txid.clone(), input.vout));
        }
    }

    if input_pub_keys.is_empty() {
        return vec![];
    }

    // Silent payments always produce taproot outputs — skip transactions without any.
    let taproot_outputs: Vec<(usize, XOnlyPublicKey)> = tx
        .output
        .iter()
        .enumerate()
        .filter_map(|(i, out)| {
            let spk = out.script_pubkey.as_bytes();
            if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
                XOnlyPublicKey::from_slice(&spk[2..]).ok().map(|pk| (i, pk))
            } else {
                None
            }
        })
        .collect();

    if taproot_outputs.is_empty() {
        return vec![];
    }

    let pubkey_refs: Vec<&secp256k1::PublicKey> = input_pub_keys.iter().collect();
    let tweak_data = match calculate_tweak_data(&pubkey_refs, &outpoints) {
        Ok(td) => td,
        Err(_) => return vec![],
    };
    let shared_secret = calculate_ecdh_shared_secret(&tweak_data, b_scan);

    let xonly_outputs: Vec<XOnlyPublicKey> = taproot_outputs.iter().map(|(_, pk)| *pk).collect();
    let found = match receiver.scan_transaction(&shared_secret, xonly_outputs) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let mut result = Vec::new();
    for map in found.values() {
        for pk in map.keys() {
            if let Some((idx, _)) = taproot_outputs.iter().find(|(_, o)| o == pk) {
                result.push(FoundPayment {
                    output_index: *idx,
                    pubkey: *pk,
                });
            }
        }
    }
    result
}

pub fn scan_block(
    receiver: &Receiver,
    b_scan: &SecretKey,
    block: &Block,
    tx_input_data: Vec<Vec<InputData>>,
) -> Vec<(bitcoin::Txid, FoundPayment)> {
    let mut all_found = Vec::new();
    // Skip coinbase (index 0); tx_input_data[i] maps to block.txdata[i+1].
    for (i, tx) in block.txdata.iter().skip(1).enumerate() {
        if let Some(inputs) = tx_input_data.get(i) {
            for payment in scan_transaction(receiver, b_scan, inputs, tx) {
                all_found.push((tx.compute_txid(), payment));
            }
        }
    }
    all_found
}
