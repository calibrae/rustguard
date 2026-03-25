// SPDX-License-Identifier: GPL-2.0

//! AllowedIPs — compressed radix trie for cryptokey routing.
//!
//! Maps IP prefixes (IPv4/IPv6 CIDR) to peer indices.
//! Used on the TX path: look up destination IP → find which peer to encrypt for.
//! Same data structure as kernel WireGuard's allowedips.c, but in safe Rust.

use kernel::alloc::KBox;
use kernel::prelude::*;

/// Maximum number of peers we support.
pub(crate) const MAX_PEERS: usize = 64;

/// A node in the radix trie.
struct TrieNode {
    /// Bit position to test (0 = MSB of first byte).
    bit: u32,
    /// Prefix length. 0 = intermediate node (no peer).
    cidr: u8,
    /// Peer index (valid when cidr > 0).
    peer_idx: usize,
    /// Children: [0] for bit=0, [1] for bit=1.
    children: [Option<KBox<TrieNode>>; 2],
}

/// AllowedIPs routing table.
pub(crate) struct AllowedIps {
    root4: Option<KBox<TrieNode>>,
    root6: Option<KBox<TrieNode>>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            bit: 0,
            cidr: 0,
            peer_idx: 0,
            children: [None, None],
        }
    }
}

impl AllowedIps {
    /// Create an empty routing table.
    pub(crate) fn new() -> Self {
        Self {
            root4: None,
            root6: None,
        }
    }

    /// Insert an IPv4 prefix → peer mapping.
    pub(crate) fn insert_v4(&mut self, ip: [u8; 4], cidr: u8, peer_idx: usize) {
        Self::insert(&mut self.root4, &ip, cidr, peer_idx);
    }

    /// Insert an IPv6 prefix → peer mapping.
    pub(crate) fn insert_v6(&mut self, ip: [u8; 16], cidr: u8, peer_idx: usize) {
        Self::insert(&mut self.root6, &ip, cidr, peer_idx);
    }

    /// Look up an IPv4 address. Returns the peer index of the longest prefix match.
    pub(crate) fn lookup_v4(&self, ip: &[u8; 4]) -> Option<usize> {
        Self::lookup(&self.root4, ip)
    }

    /// Look up an IPv6 address. Returns the peer index of the longest prefix match.
    pub(crate) fn lookup_v6(&self, ip: &[u8; 16]) -> Option<usize> {
        Self::lookup(&self.root6, ip)
    }

    /// Look up a packet's destination IP. Inspects the IP version byte.
    /// Returns the peer index or None.
    pub(crate) fn lookup_packet(&self, packet: &[u8]) -> Option<usize> {
        if packet.is_empty() {
            return None;
        }
        let version = packet[0] >> 4;
        match version {
            4 if packet.len() >= 20 => {
                let dst: [u8; 4] = packet[16..20].try_into().ok()?;
                self.lookup_v4(&dst)
            }
            6 if packet.len() >= 40 => {
                let dst: [u8; 16] = packet[24..40].try_into().ok()?;
                self.lookup_v6(&dst)
            }
            _ => None,
        }
    }

    /// Remove all entries for a specific peer.
    pub(crate) fn remove_by_peer(&mut self, peer_idx: usize) {
        Self::remove_peer(&mut self.root4, peer_idx);
        Self::remove_peer(&mut self.root6, peer_idx);
    }

    // ── Internal ──────────────────────────────────────────────────────

    fn insert(root: &mut Option<KBox<TrieNode>>, ip: &[u8], cidr: u8, peer_idx: usize) {
        let node = match root {
            Some(ref mut n) => n,
            None => {
                if let Ok(n) = KBox::new(TrieNode::new(), GFP_KERNEL) {
                    *root = Some(n);
                } else {
                    return;
                }
                root.as_mut().unwrap()
            }
        };

        if cidr == 0 {
            // Default route — match everything.
            node.cidr = 0;
            node.peer_idx = peer_idx;
            // Store with a sentinel: cidr=255 means "this is a default route"
            node.cidr = 255; // special: default
            node.peer_idx = peer_idx;
            return;
        }

        Self::insert_recursive(node, ip, cidr, peer_idx, 0);
    }

    fn insert_recursive(
        node: &mut TrieNode, ip: &[u8], cidr: u8, peer_idx: usize, depth: u32,
    ) {
        if depth >= cidr as u32 {
            // We've consumed all prefix bits — store the peer here.
            node.cidr = cidr;
            node.peer_idx = peer_idx;
            return;
        }

        let bit = Self::get_bit(ip, depth);
        let child = &mut node.children[bit as usize];

        if child.is_none() {
            if let Ok(n) = KBox::new(TrieNode::new(), GFP_KERNEL) {
                *child = Some(n);
            } else {
                return;
            }
        }

        Self::insert_recursive(child.as_mut().unwrap(), ip, cidr, peer_idx, depth + 1);
    }

    fn lookup(root: &Option<KBox<TrieNode>>, ip: &[u8]) -> Option<usize> {
        let node = root.as_ref()?;

        // Track the longest prefix match as we walk down.
        let mut best_match: Option<usize> = None;

        // Check if root has a default route.
        if node.cidr == 255 {
            best_match = Some(node.peer_idx);
        }

        Self::lookup_recursive(node, ip, 0, &mut best_match);
        best_match
    }

    fn lookup_recursive(
        node: &TrieNode, ip: &[u8], depth: u32, best: &mut Option<usize>,
    ) {
        // If this node has a prefix match, update best.
        if node.cidr > 0 && node.cidr != 255 {
            *best = Some(node.peer_idx);
        }

        let bit = Self::get_bit(ip, depth);
        if let Some(ref child) = node.children[bit as usize] {
            // Check child for default/prefix match.
            if child.cidr == 255 || (child.cidr > 0 && child.cidr != 255) {
                *best = Some(child.peer_idx);
            }
            Self::lookup_recursive(child, ip, depth + 1, best);
        }
    }

    fn remove_peer(root: &mut Option<KBox<TrieNode>>, peer_idx: usize) {
        if let Some(ref mut node) = root {
            Self::remove_peer_recursive(node, peer_idx);
        }
    }

    fn remove_peer_recursive(node: &mut TrieNode, peer_idx: usize) {
        if node.peer_idx == peer_idx && node.cidr > 0 {
            node.cidr = 0;
        }
        for child in &mut node.children {
            if let Some(ref mut c) = child {
                Self::remove_peer_recursive(c, peer_idx);
            }
        }
    }

    /// Get the bit at position `pos` in a byte array (MSB first).
    fn get_bit(data: &[u8], pos: u32) -> u8 {
        let byte_idx = (pos / 8) as usize;
        let bit_idx = 7 - (pos % 8);
        if byte_idx < data.len() {
            (data[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }
}
