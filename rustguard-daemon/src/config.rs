//! WireGuard configuration file parser.
//!
//! Parses the standard INI-style wg0.conf format that every WireGuard
//! implementation understands. Muscle memory compatible.

use base64::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::{fs, io};

/// Parsed WireGuard configuration.
#[derive(Debug)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug)]
pub struct InterfaceConfig {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub address_v6: Option<(Ipv6Addr, u8)>,
}

#[derive(Debug)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<CidrAddr>,
    pub persistent_keepalive: Option<u16>,
}

/// An IP address with prefix length (CIDR notation). Supports v4 and v6.
#[derive(Debug, Clone)]
pub struct CidrAddr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl CidrAddr {
    /// Check if a given IP falls within this CIDR range.
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        match self.addr {
            IpAddr::V4(net) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = if self.prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                let net: u32 = net.into();
                let target: u32 = ip.into();
                (net & mask) == (target & mask)
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Check if a given IPv6 address falls within this CIDR range.
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        match self.addr {
            IpAddr::V4(_) => false,
            IpAddr::V6(net) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net = u128::from(net);
                let target = u128::from(ip);
                let mask = if self.prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (net & mask) == (target & mask)
            }
        }
    }

    /// Check if a given IP (v4 or v6) falls within this CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }
}

impl std::fmt::Display for CidrAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Config {
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::parse(&contents)
    }

    pub fn parse(input: &str) -> io::Result<Self> {
        let interface;
        let mut peers = Vec::new();
        let mut current_section: Option<&str> = None;

        // Accumulate key-value pairs per section.
        let mut iface_kvs: Vec<(&str, &str)> = Vec::new();
        let mut current_peer_kvs: Vec<(&str, &str)> = Vec::new();

        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.eq_ignore_ascii_case("[Interface]") {
                // Flush any in-progress peer before switching to interface.
                if current_section == Some("peer") && !current_peer_kvs.is_empty() {
                    peers.push(parse_peer(&current_peer_kvs)?);
                    current_peer_kvs.clear();
                }
                current_section = Some("interface");
                continue;
            }
            if line.eq_ignore_ascii_case("[Peer]") {
                // Flush previous peer if any.
                if current_section == Some("peer") && !current_peer_kvs.is_empty() {
                    peers.push(parse_peer(&current_peer_kvs)?);
                    current_peer_kvs.clear();
                }
                current_section = Some("peer");
                continue;
            }

            let (key, value) = line.split_once('=').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad line: {line}"))
            })?;
            let key = key.trim();
            let value = value.trim();

            match current_section {
                Some("interface") => iface_kvs.push((key, value)),
                Some("peer") => current_peer_kvs.push((key, value)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("key outside section: {line}"),
                    ))
                }
            }
        }

        // Flush last peer.
        if !current_peer_kvs.is_empty() {
            peers.push(parse_peer(&current_peer_kvs)?);
        }

        interface = Some(parse_interface(&iface_kvs)?);

        Ok(Config {
            interface: interface
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no [Interface]"))?,
            peers,
        })
    }
}

fn decode_key(s: &str) -> io::Result<[u8; 32]> {
    let bytes = BASE64_STANDARD
        .decode(s)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key must be 32 bytes"))
}

fn parse_interface(kvs: &[(&str, &str)]) -> io::Result<InterfaceConfig> {
    let mut private_key = None;
    let mut listen_port = 51820u16;
    let mut address = None;
    let mut netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut address_v6 = None;

    for &(key, value) in kvs {
        match key.to_ascii_lowercase().as_str() {
            "privatekey" => private_key = Some(decode_key(value)?),
            "listenport" => {
                listen_port = value.parse().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad port: {e}"))
                })?
            }
            "address" => {
                // Support comma-separated v4 and v6: "10.0.0.1/24, fd15::1/64"
                for part in value.split(',') {
                    let part = part.trim();
                    let (addr_str, prefix_opt) = part.split_once('/').map(|(a, p)| (a, Some(p))).unwrap_or((part, None));

                    if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
                        let prefix = prefix_opt.unwrap_or("24");
                        let prefix_len: u8 = prefix.parse().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("bad prefix: {e}"))
                        })?;
                        address = Some(v4);
                        netmask = prefix_to_netmask(prefix_len);
                    } else if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
                        let prefix = prefix_opt.unwrap_or("64");
                        let prefix_len: u8 = prefix.parse().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("bad prefix: {e}"))
                        })?;
                        address_v6 = Some((v6, prefix_len));
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("bad address: {addr_str}"),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(InterfaceConfig {
        private_key: private_key
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PrivateKey"))?,
        listen_port,
        address: address
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Address"))?,
        netmask,
        address_v6,
    })
}

fn parse_peer(kvs: &[(&str, &str)]) -> io::Result<PeerConfig> {
    let mut public_key = None;
    let mut preshared_key = None;
    let mut endpoint = None;
    let mut allowed_ips = Vec::new();
    let mut persistent_keepalive = None;

    for &(key, value) in kvs {
        match key.to_ascii_lowercase().as_str() {
            "publickey" => public_key = Some(decode_key(value)?),
            "presharedkey" => preshared_key = Some(decode_key(value)?),
            "endpoint" => {
                endpoint = Some(value.parse::<SocketAddr>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad endpoint: {e}"))
                })?)
            }
            "allowedips" => {
                for cidr in value.split(',') {
                    allowed_ips.push(parse_cidr(cidr.trim())?);
                }
            }
            "persistentkeepalive" => {
                persistent_keepalive = Some(value.parse::<u16>().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("bad keepalive: {e}"),
                    )
                })?)
            }
            _ => {}
        }
    }

    Ok(PeerConfig {
        public_key: public_key
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing PublicKey"))?,
        preshared_key,
        endpoint,
        allowed_ips,
        persistent_keepalive,
    })
}

fn parse_cidr(s: &str) -> io::Result<CidrAddr> {
    // Default prefix: 32 for v4, 128 for v6.
    let (addr_str, prefix_str_opt) = s.split_once('/').map(|(a, p)| (a, Some(p))).unwrap_or((s, None));
    let addr = addr_str.parse::<IpAddr>().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bad CIDR addr: {e}"))
    })?;
    let default_prefix = if addr.is_ipv4() { "32" } else { "128" };
    let prefix_len = prefix_str_opt.unwrap_or(default_prefix).parse::<u8>().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bad CIDR prefix: {e}"))
    })?;
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("prefix length {prefix_len} exceeds maximum {max_prefix} for address {addr}"),
        ));
    }
    Ok(CidrAddr { addr, prefix_len })
}

pub fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else if prefix >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
[Interface]
PrivateKey = cGiPH7CqyNOCaW6ykZLH9K3Bt0enk5rDiTcv1O3A+JA=
ListenPort = 51820
Address = 10.0.0.1/24

[Peer]
PublicKey = HhMN8JntZEa8iF6bc+BdJD8MGD9shwefov5Gt+95Ky8=
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = 203.0.113.1:51820
PersistentKeepalive = 25

[Peer]
PublicKey = tNwlJsp4WIaPpeCYNsleoE8QzJFVBLHYEHLgHVQ4NyQ=
AllowedIPs = 10.0.0.3/32
"#;

    #[test]
    fn parse_full_config() {
        let config = Config::parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(config.interface.listen_port, 51820);
        assert_eq!(config.interface.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.interface.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(config.peers.len(), 2);

        let peer1 = &config.peers[0];
        assert_eq!(
            peer1.endpoint,
            Some("203.0.113.1:51820".parse().unwrap())
        );
        assert_eq!(peer1.allowed_ips.len(), 2);
        assert_eq!(peer1.persistent_keepalive, Some(25));

        let peer2 = &config.peers[1];
        assert!(peer2.endpoint.is_none());
        assert_eq!(peer2.allowed_ips.len(), 1);
    }

    #[test]
    fn cidr_contains_v4() {
        let cidr = CidrAddr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
        };
        assert!(cidr.contains_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(cidr.contains_v4(Ipv4Addr::new(10, 0, 0, 254)));
        assert!(!cidr.contains_v4(Ipv4Addr::new(10, 0, 1, 1)));
    }

    #[test]
    fn cidr_contains_host() {
        let cidr = CidrAddr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            prefix_len: 32,
        };
        assert!(cidr.contains_v4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(!cidr.contains_v4(Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn cidr_contains_default_route() {
        let cidr = CidrAddr {
            addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 0,
        };
        assert!(cidr.contains_v4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(cidr.contains_v4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn cidr_contains_v6() {
        let cidr = CidrAddr {
            addr: IpAddr::V6("fd00::".parse().unwrap()),
            prefix_len: 64,
        };
        assert!(cidr.contains_v6("fd00::1".parse().unwrap()));
        assert!(cidr.contains_v6("fd00::ffff".parse().unwrap()));
        assert!(!cidr.contains_v6("fd01::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_does_not_match_v6() {
        let cidr = CidrAddr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        };
        assert!(!cidr.contains_v6("fd00::1".parse().unwrap()));
    }

    #[test]
    fn parse_v6_allowed_ips() {
        let config = Config::parse(
            r#"
[Interface]
PrivateKey = cGiPH7CqyNOCaW6ykZLH9K3Bt0enk5rDiTcv1O3A+JA=
ListenPort = 51820
Address = 10.0.0.1/24

[Peer]
PublicKey = HhMN8JntZEa8iF6bc+BdJD8MGD9shwefov5Gt+95Ky8=
AllowedIPs = 10.0.0.2/32, fd00::/64
"#,
        )
        .unwrap();
        assert_eq!(config.peers[0].allowed_ips.len(), 2);
        assert!(config.peers[0].allowed_ips[1].addr.is_ipv6());
    }
}
