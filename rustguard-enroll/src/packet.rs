//! Raw packet parsing for AF_XDP frames.
//!
//! AF_XDP gives us full Ethernet frames. We need to strip L2/L3/L4
//! headers to get the WireGuard payload, and extract the source address.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parsed UDP payload from a raw Ethernet frame.
pub struct ParsedUdp<'a> {
    pub src_addr: SocketAddr,
    pub payload: &'a [u8],
}

/// Parse a raw Ethernet frame, extract UDP payload and source address.
/// Returns None if not a UDP packet or too short.
pub fn parse_eth_udp(frame: &[u8]) -> Option<ParsedUdp<'_>> {
    if frame.len() < 14 {
        return None; // Too short for Ethernet.
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        0x0800 => parse_ipv4_udp(&frame[14..]),   // IPv4
        0x86DD => parse_ipv6_udp(&frame[14..]),    // IPv6
        _ => None,
    }
}

fn parse_ipv4_udp(ip_data: &[u8]) -> Option<ParsedUdp<'_>> {
    if ip_data.len() < 20 {
        return None;
    }

    let ihl = (ip_data[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return None; // IHL below minimum IPv4 header size.
    }
    let protocol = ip_data[9];
    if protocol != 17 {
        return None; // Not UDP.
    }
    if ip_data.len() < ihl + 8 {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);
    let src_port = u16::from_be_bytes([ip_data[ihl], ip_data[ihl + 1]]);
    let payload = &ip_data[ihl + 8..];

    Some(ParsedUdp {
        src_addr: SocketAddr::from((src_ip, src_port)),
        payload,
    })
}

fn parse_ipv6_udp(ip6_data: &[u8]) -> Option<ParsedUdp<'_>> {
    if ip6_data.len() < 40 {
        return None;
    }

    let next_header = ip6_data[6];
    if next_header != 17 {
        return None; // Not UDP (or has extension headers — skip for now).
    }
    if ip6_data.len() < 48 {
        return None;
    }

    let mut src_ip_bytes = [0u8; 16];
    src_ip_bytes.copy_from_slice(&ip6_data[8..24]);
    let src_ip = Ipv6Addr::from(src_ip_bytes);
    let src_port = u16::from_be_bytes([ip6_data[40], ip6_data[41]]);
    let payload = &ip6_data[48..];

    Some(ParsedUdp {
        src_addr: SocketAddr::from((src_ip, src_port)),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_udp_frame() {
        // Minimal Ethernet + IPv4 + UDP frame.
        let mut frame = vec![0u8; 14 + 20 + 8 + 4]; // eth + ip + udp + payload
        // Ethernet: ethertype = 0x0800 (IPv4)
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IPv4: version=4, ihl=5, protocol=17 (UDP)
        frame[14] = 0x45;
        frame[23] = 17; // protocol
        frame[26] = 10; frame[27] = 0; frame[28] = 0; frame[29] = 1; // src IP
        // UDP: src port = 12345
        frame[34] = (12345 >> 8) as u8;
        frame[35] = (12345 & 0xff) as u8;
        // Payload
        frame[42] = 0xAA;
        frame[43] = 0xBB;
        frame[44] = 0xCC;
        frame[45] = 0xDD;

        let parsed = parse_eth_udp(&frame).unwrap();
        assert_eq!(
            parsed.src_addr,
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 12345))
        );
        assert_eq!(parsed.payload, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
