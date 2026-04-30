use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

use bitcoin::{hashes::Hash, Amount, Block, OutPoint, Txid};

const MAGIC: &[u8; 4] = b"SP02";

#[derive(Debug, Clone)]
pub struct SpentBy {
    pub txid: Txid,
    pub block_height: u32,
}

#[derive(Debug, Clone)]
pub struct OwnedUtxo {
    pub value: Amount,
    pub block_height: u32,
    pub spent_by: Option<SpentBy>,
}

pub enum HistoryEntry {
    Received {
        outpoint: OutPoint,
        value: Amount,
        block_height: u32,
    },
    Spent {
        outpoint: OutPoint,
        value: Amount,
        spent_at: u32,
    },
}

pub struct SilentPaymentWallet {
    pub scan_height: u32,
    utxos: HashMap<OutPoint, OwnedUtxo>,
}

impl Default for SilentPaymentWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl SilentPaymentWallet {
    pub fn new() -> Self {
        Self {
            scan_height: 0,
            utxos: HashMap::new(),
        }
    }

    pub fn process_block(
        &mut self,
        block: &Block,
        block_height: u32,
        found: &[(Txid, usize, Amount)],
    ) {
        for (txid, vout, value) in found {
            let outpoint = OutPoint {
                txid: *txid,
                vout: *vout as u32,
            };
            self.utxos.insert(
                outpoint,
                OwnedUtxo {
                    value: *value,
                    block_height,
                    spent_by: None,
                },
            );
        }

        for tx in &block.txdata {
            let spending_txid = tx.compute_txid();
            for input in &tx.input {
                if let Some(utxo) = self.utxos.get_mut(&input.previous_output) {
                    utxo.spent_by = Some(SpentBy {
                        txid: spending_txid,
                        block_height,
                    });
                }
            }
        }

        self.scan_height = block_height;
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.values().filter(|u| u.spent_by.is_none()).count()
    }

    pub fn balance(&self) -> Amount {
        self.utxos
            .values()
            .filter(|u| u.spent_by.is_none())
            .map(|u| u.value)
            .fold(Amount::ZERO, |acc, v| acc + v)
    }

    pub fn history(&self) -> Vec<HistoryEntry> {
        let mut entries: Vec<HistoryEntry> = self
            .utxos
            .iter()
            .flat_map(|(outpoint, utxo)| {
                let mut v = vec![HistoryEntry::Received {
                    outpoint: *outpoint,
                    value: utxo.value,
                    block_height: utxo.block_height,
                }];
                if let Some(ref s) = utxo.spent_by {
                    v.push(HistoryEntry::Spent {
                        outpoint: *outpoint,
                        value: utxo.value,
                        spent_at: s.block_height,
                    });
                }
                v
            })
            .collect();

        entries.sort_by_key(|e| match e {
            HistoryEntry::Received { block_height, .. } => *block_height,
            HistoryEntry::Spent { spent_at, .. } => *spent_at,
        });
        entries
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut f = File::create(path)?;
        f.write_all(MAGIC)?;
        f.write_all(&self.scan_height.to_le_bytes())?;
        let count = self.utxos.len() as u32;
        f.write_all(&count.to_le_bytes())?;
        for (outpoint, utxo) in &self.utxos {
            f.write_all(outpoint.txid.as_ref())?;
            f.write_all(&outpoint.vout.to_le_bytes())?;
            f.write_all(&utxo.value.to_sat().to_le_bytes())?;
            f.write_all(&utxo.block_height.to_le_bytes())?;
            match &utxo.spent_by {
                None => f.write_all(&[0u8])?,
                Some(s) => {
                    f.write_all(&[1u8])?;
                    f.write_all(s.txid.as_ref())?;
                    f.write_all(&s.block_height.to_le_bytes())?;
                }
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let mut f = File::open(path)?;
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let mut buf4 = [0u8; 4];
        f.read_exact(&mut buf4)?;
        let scan_height = u32::from_le_bytes(buf4);
        f.read_exact(&mut buf4)?;
        let count = u32::from_le_bytes(buf4);
        let mut utxos = HashMap::new();
        for _ in 0..count {
            let mut txid_bytes = [0u8; 32];
            f.read_exact(&mut txid_bytes)?;
            let txid = Txid::from_byte_array(txid_bytes);
            f.read_exact(&mut buf4)?;
            let vout = u32::from_le_bytes(buf4);
            let mut buf8 = [0u8; 8];
            f.read_exact(&mut buf8)?;
            let value = Amount::from_sat(u64::from_le_bytes(buf8));
            f.read_exact(&mut buf4)?;
            let block_height = u32::from_le_bytes(buf4);
            let mut spent_flag = [0u8; 1];
            f.read_exact(&mut spent_flag)?;
            let spent_by = if spent_flag[0] == 1 {
                let mut stxid_bytes = [0u8; 32];
                f.read_exact(&mut stxid_bytes)?;
                let stxid = Txid::from_byte_array(stxid_bytes);
                f.read_exact(&mut buf4)?;
                let sbh = u32::from_le_bytes(buf4);
                Some(SpentBy {
                    txid: stxid,
                    block_height: sbh,
                })
            } else {
                None
            };
            utxos.insert(
                OutPoint { txid, vout },
                OwnedUtxo {
                    value,
                    block_height,
                    spent_by,
                },
            );
        }
        Ok(Self { scan_height, utxos })
    }
}
