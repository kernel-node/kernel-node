use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{serialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::io::from_std_mut;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::script::Builder;
use bitcoin::transaction;
use bitcoin::{
    Amount, Block, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Witness,
};

const PROTOCOL_VERSION: u32 = 70016;

pub fn version(height: u64) -> VersionMessage {
    let unused = Address::new(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        ServiceFlags::NONE,
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    VersionMessage {
        version: PROTOCOL_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: i64::try_from(now.as_secs()).unwrap(),
        receiver: unused.clone(),
        sender: unused,
        nonce: 0,
        user_agent: "/scripted-peer/".to_string(),
        start_height: i32::try_from(height).unwrap(),
        relay: false,
    }
}

pub fn send(stream: &mut TcpStream, payload: NetworkMessage) -> io::Result<()> {
    let message = RawNetworkMessage::new(Network::Regtest.magic(), payload);
    stream.write_all(&serialize(&message))
}

pub fn receive(reader: &mut BufReader<TcpStream>) -> io::Result<NetworkMessage> {
    let message =
        RawNetworkMessage::consensus_decode(from_std_mut(reader)).map_err(io::Error::other)?;
    Ok(message.into_payload())
}

pub fn regtest_chain(len: u64) -> Vec<Block> {
    let mut prev = genesis_block(Network::Regtest).header;
    let mut blocks = Vec::new();
    for height in 1..=len {
        let coinbase = Transaction {
            version: transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                // BIP34 height, padded to the two-byte minimum.
                script_sig: Builder::new()
                    .push_int(i64::try_from(height).unwrap())
                    .push_int(0)
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: prev.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: prev.time + 1,
                bits: prev.bits,
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        prev = block.header;
        blocks.push(block);
    }
    blocks
}
