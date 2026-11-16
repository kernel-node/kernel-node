use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::consensus::{serialize, Decodable};
use bitcoin::io::from_std_mut;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;

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
