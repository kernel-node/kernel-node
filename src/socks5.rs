use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    time::Duration,
};

use bitcoin_hashes::sha3_256;

const VERSION: u8 = 5;
const NOAUTH: u8 = 0;
const METHODS: u8 = 1;
const CMD_CONNECT: u8 = 1;
const RESPONSE_SUCCESS: u8 = 0;
const RSV: u8 = 0;
const ADDR_TYPE_IPV4: u8 = 1;
const ADDR_TYPE_DOMAIN: u8 = 3;
const ADDR_TYPE_IPV6: u8 = 4;

const SALT: &[u8] = b".onion checksum";
const TOR_VERSION: u8 = 0x03;
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

// Maximum allowed time to wait for Tor to bootstrap before trying a new connection.
const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);
// Timeout to reach the local proxy. This should be hosted on the local machine usually.
const SOCKS_SERVER_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub struct OnionAddress([u8; 32]);

impl OnionAddress {
    pub const fn from_pubkey(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl core::fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let buf = pubkey_to_service(&self.0);
        f.write_str(std::str::from_utf8(&buf).expect("ASCII"))
    }
}

pub trait SocksDestination {
    type Encoded: AsRef<[u8]>;
    const TYPE_BYTE: u8;
    fn encode(&self) -> Self::Encoded;
}

impl SocksDestination for OnionAddress {
    type Encoded = [u8; 63];
    const TYPE_BYTE: u8 = ADDR_TYPE_DOMAIN;

    fn encode(&self) -> [u8; 63] {
        let service = pubkey_to_service(&self.0);
        let mut out = [0u8; 63];
        out[0] = 62;
        out[1..].copy_from_slice(&service);
        out
    }
}

impl SocksDestination for Ipv4Addr {
    type Encoded = [u8; 4];
    const TYPE_BYTE: u8 = ADDR_TYPE_IPV4;

    fn encode(&self) -> [u8; 4] {
        self.octets()
    }
}

impl SocksDestination for Ipv6Addr {
    type Encoded = [u8; 16];
    const TYPE_BYTE: u8 = ADDR_TYPE_IPV6;

    fn encode(&self) -> [u8; 16] {
        self.octets()
    }
}

#[derive(Debug, Clone)]
pub struct Socks5Proxy {
    proxy: SocketAddr,
    timeout: Duration,
}

impl Socks5Proxy {
    pub const fn from_proxy_socket_addr(proxy: SocketAddr) -> Self {
        Self {
            proxy,
            timeout: SOCKS_SERVER_TIMEOUT,
        }
    }

    pub fn connect<D: SocksDestination>(
        &self,
        addr: D,
        port: u16,
        read_timeout: Duration,
    ) -> std::io::Result<TcpStream> {
        let mut tcp_stream = TcpStream::connect_timeout(&self.proxy, self.timeout)?;
        tcp_stream.set_read_timeout(Some(TOR_BOOTSTRAP_TIMEOUT))?;
        tcp_stream.set_write_timeout(Some(TOR_BOOTSTRAP_TIMEOUT))?;
        tcp_stream.write_all(&[VERSION, METHODS, NOAUTH])?;
        let mut resp_buf = [0_u8; 2];
        tcp_stream.read_exact(&mut resp_buf)?;
        if resp_buf[0] != VERSION {
            return Err(std::io::Error::other("unsupported socks protocol version"));
        }
        if resp_buf[1] != NOAUTH {
            return Err(std::io::Error::other("socks proxy requires authentication"));
        }
        let dest_bytes = addr.encode();
        tcp_stream.write_all(&[VERSION, CMD_CONNECT, RSV, D::TYPE_BYTE])?;
        tcp_stream.write_all(dest_bytes.as_ref())?;
        tcp_stream.write_all(&port.to_be_bytes())?;
        let mut resp_buf = [0_u8; 4];
        tcp_stream.read_exact(&mut resp_buf)?;
        if resp_buf[0] != VERSION {
            return Err(std::io::Error::other("unsupported socks protocol version"));
        }
        if resp_buf[1] != RESPONSE_SUCCESS {
            return Err(std::io::Error::other("response failure"));
        }
        match resp_buf[3] {
            ADDR_TYPE_IPV4 => {
                // Read the IPv4 address and additional two bytes for the port
                let mut buf = [0_u8; 6];
                tcp_stream.read_exact(&mut buf)?;
            }
            ADDR_TYPE_IPV6 => {
                // Read the IPv6 address and additional two bytes for the port
                let mut buf = [0_u8; 18];
                tcp_stream.read_exact(&mut buf)?;
            }
            ADDR_TYPE_DOMAIN => {
                let mut len = [0_u8; 1];
                tcp_stream.read_exact(&mut len)?;
                let mut buf = vec![0_u8; u8::from_le_bytes(len) as usize + 2];
                tcp_stream.read_exact(&mut buf)?;
            }
            _ => return Err(std::io::Error::other("response failure")),
        }
        tcp_stream.set_read_timeout(Some(read_timeout))?;
        tcp_stream.set_write_timeout(None)?;
        Ok(tcp_stream)
    }
}

#[inline(always)]
fn pubkey_to_service(ed25519: &[u8; 32]) -> [u8; 62] {
    // SHA3(".onion checksum" + public key + version)
    let mut cs_input = [0u8; 48];
    cs_input[..15].copy_from_slice(SALT);
    cs_input[15..47].copy_from_slice(ed25519);
    cs_input[47] = TOR_VERSION;
    let cs = sha3_256::hash(&cs_input).to_byte_array();
    // Onion address = public key + 2 byte checksum + version
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(ed25519);
    payload[32] = cs[0];
    payload[33] = cs[1];
    payload[34] = TOR_VERSION;
    let encoded = base32_encode_35(&payload);
    let mut out = [0u8; 62];
    out[..56].copy_from_slice(&encoded);
    out[56..].copy_from_slice(b".onion");
    out
}

#[inline(always)]
fn base32_encode_35(data: &[u8; 35]) -> [u8; 56] {
    let mut out = [0u8; 56];
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;
    let mut i = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            out[i] = ALPHABET[((buffer >> bits_left) & 0x1f) as usize];
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::pubkey_to_service;
    use bitcoin::hex::FromHex;

    #[test]
    fn public_key_to_service() {
        let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let hsid = <[u8; 32]>::from_hex(hex).unwrap();
        let service = pubkey_to_service(&hsid);
        assert_eq!(
            b"25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion",
            &service
        );
    }
}
