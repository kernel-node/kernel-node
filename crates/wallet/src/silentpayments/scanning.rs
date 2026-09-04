use ::silentpayments::{
    receiving::{Label, Receiver},
    utils::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input},
};
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Txid};
use bitcoin::{
    secp256k1::{self, Scalar, SecretKey, XOnlyPublicKey},
    Script,
};
use bitcoinkernel::prelude::{
    BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt, TransactionExt, TransactionSpentOutputsExt,
    TxInExt, TxOutExt, TxOutPointExt, TxidExt, WitnessStackExt,
};

use crate::silentpayments::wallet::Coin;

pub struct InputData {
    pub script_sig: Vec<u8>,
    pub witness: Vec<Vec<u8>>,
    pub prevout_script: Vec<u8>,
    pub outpoint: silentpayments::utils::OutPoint,
}

pub fn scan_transaction(
    receiver: &Receiver,
    b_scan: &SecretKey,
    inputs: &[InputData],
    taproot_outputs: &[(usize, XOnlyPublicKey)],
) -> Vec<(usize, Scalar, Option<Label>)> {
    let mut input_pub_keys = Vec::new();
    let mut outpoints = Vec::new();
    for input in inputs {
        if let Ok(Some(pk)) =
            get_pubkey_from_input(&input.script_sig, &input.witness, &input.prevout_script)
        {
            input_pub_keys.push(pk);
            outpoints.push(input.outpoint);
        }
    }

    if input_pub_keys.is_empty() {
        return vec![];
    }

    let pubkey_refs: Vec<&secp256k1::PublicKey> = input_pub_keys.iter().collect();
    let tweak_data = match calculate_tweak_data(&pubkey_refs, &outpoints) {
        Ok(td) => td,
        Err(_) => return vec![],
    };
    let shared_secret = calculate_ecdh_shared_secret(&tweak_data, b_scan);

    let xonly_outputs: Vec<XOnlyPublicKey> = taproot_outputs.iter().map(|(_, pk)| *pk).collect();
    let found = match receiver.scan_transaction(&shared_secret, &xonly_outputs) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let mut result = Vec::new();
    for (label, pubkey_map) in found.iter() {
        for (pk, tweak) in pubkey_map {
            if let Some((idx, _)) = taproot_outputs.iter().find(|(_, o)| o == pk) {
                result.push((*idx, *tweak, label.clone()));
            }
        }
    }
    result
}

pub(crate) fn scan_block_inner(
    receiver: &Receiver,
    b_scan: &SecretKey,
    kernel_block: &bitcoinkernel::Block,
    spent_outputs: bitcoinkernel::BlockSpentOutputs,
    block_height: u32,
) -> Vec<(OutPoint, Coin)> {
    let mut found: Vec<(OutPoint, Coin)> = Vec::new();

    // Skip coinbase; spent_outputs[i] maps to kernel_block.transactions().skip(1)[i].
    for (kernel_tx, tx_spent) in kernel_block
        .transactions()
        .skip(1)
        .zip(spent_outputs.iter())
    {
        let taproot_outputs: Vec<(usize, XOnlyPublicKey)> = kernel_tx
            .outputs()
            .enumerate()
            .filter_map(|(i, out)| parse_p2tr(out.script_pubkey().as_bytes()).map(|pk| (i, pk)))
            .collect();

        if taproot_outputs.is_empty() {
            continue;
        }

        let mut inputs: Vec<InputData> = Vec::with_capacity(kernel_tx.input_count());
        for (idx, input) in kernel_tx.inputs().enumerate() {
            let coin = tx_spent
                .coin(idx)
                .expect("input/spent-output count mismatch");
            let outpoint = input.outpoint();
            let mut buf = [0u8; 36];
            buf[..32].copy_from_slice(&outpoint.txid().to_bytes());
            buf[32..].copy_from_slice(&outpoint.index().to_le_bytes());
            let witness: Vec<Vec<u8>> = input.witness_stack().items().collect();
            let script_sig = input.script_sig().unwrap_or_default();
            inputs.push(InputData {
                script_sig,
                witness,
                prevout_script: coin.output().script_pubkey().to_bytes(),
                outpoint: silentpayments::utils::OutPoint::from_bytes(buf),
            });
        }

        let matches = scan_transaction(receiver, b_scan, &inputs, &taproot_outputs);
        if matches.is_empty() {
            continue;
        }

        let txid = Txid::from_byte_array(kernel_tx.txid().to_bytes());
        for (output_index, tweak, label) in matches {
            let out = kernel_tx
                .output(output_index)
                .expect("index came from this tx");
            found.push((
                OutPoint {
                    txid,
                    vout: output_index as u32,
                },
                Coin {
                    value: Amount::from_sat(out.value() as u64),
                    script_pubkey: ScriptBuf::from(out.script_pubkey().to_bytes()),
                    tweak,
                    label: label.map(|l| l.into_inner()),
                    block_height,
                    spent_by: None,
                },
            ));
        }
    }
    found
}

#[inline]
fn parse_p2tr(script: &[u8]) -> Option<XOnlyPublicKey> {
    let script = Script::from_bytes(script);
    if script.is_p2tr() {
        XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).ok()
    } else {
        None
    }
}
