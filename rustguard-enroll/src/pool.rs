//! IP address pool for dynamic peer assignment.
//!
//! Manages a CIDR range and hands out addresses to new peers.
//! The first address (.1) is reserved for the server.

use std::collections::HashSet;
use std::net::Ipv4Addr;

pub struct IpPool {
    /// Network address (e.g. 10.150.0.0).
    network: u32,
    /// Prefix length (e.g. 24).
    pub prefix_len: u8,
    /// Number of usable host addresses.
    capacity: u32,
    /// Addresses currently assigned.
    assigned: HashSet<Ipv4Addr>,
    /// The server's own address (first in range).
    pub server_addr: Ipv4Addr,
}

impl IpPool {
    /// Create a pool from a CIDR (e.g. "10.150.0.0/24").
    /// The .1 address is reserved for the server.
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 30 {
            return None; // Need at least 2 usable addresses.
        }

        let net: u32 = network.into();
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let net = net & mask; // Normalize.
        let capacity = !mask; // Number of addresses in the range (including network + broadcast).

        let server_addr = Ipv4Addr::from(net + 1);
        let mut assigned = HashSet::new();
        assigned.insert(server_addr);

        Some(Self {
            network: net,
            prefix_len,
            capacity,
            assigned,
            server_addr,
        })
    }

    /// Allocate the next available IP address.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Start from .2 (server is .1), skip network (.0) and broadcast (last).
        for offset in 2..self.capacity {
            let addr = Ipv4Addr::from(self.network + offset);
            if !self.assigned.contains(&addr) {
                self.assigned.insert(addr);
                return Some(addr);
            }
        }
        None // Pool exhausted.
    }

    /// Release an address back to the pool.
    pub fn release(&mut self, addr: Ipv4Addr) {
        if addr != self.server_addr {
            self.assigned.remove(&addr);
        }
    }

    /// Check if an address belongs to this pool.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let a: u32 = addr.into();
        let mask = u32::MAX << (32 - self.prefix_len);
        (a & mask) == self.network
    }

    /// Number of addresses currently assigned (including server).
    pub fn assigned_count(&self) -> usize {
        self.assigned.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_allocation() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 150, 0, 0), 24).unwrap();
        assert_eq!(pool.server_addr, Ipv4Addr::new(10, 150, 0, 1));

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 150, 0, 2));

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 150, 0, 3));
    }

    #[test]
    fn release_and_reuse() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), 30).unwrap();
        // /30 = 4 addresses: .0 (network), .1 (server), .2 (usable), .3 (broadcast)
        let ip = pool.allocate().unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 2));

        assert!(pool.allocate().is_none()); // Only one client address in /30.

        pool.release(ip);
        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn pool_exhaustion() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        // /29 = 8 addresses: .0 net, .1 server, .2-.6 clients, .7 broadcast
        let mut allocated = Vec::new();
        for _ in 0..5 {
            allocated.push(pool.allocate().unwrap());
        }
        assert!(pool.allocate().is_none());
        assert_eq!(allocated.len(), 5);
    }

    #[test]
    fn contains_check() {
        let pool = IpPool::new(Ipv4Addr::new(10, 150, 0, 0), 24).unwrap();
        assert!(pool.contains(Ipv4Addr::new(10, 150, 0, 42)));
        assert!(!pool.contains(Ipv4Addr::new(10, 151, 0, 1)));
    }

    #[test]
    fn server_addr_not_released() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        pool.release(pool.server_addr); // Should be a no-op.
        // Server addr should still be in use — next allocation starts at .2.
        let ip = pool.allocate().unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 2));
    }
}
