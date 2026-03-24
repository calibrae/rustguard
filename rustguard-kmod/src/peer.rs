// SPDX-License-Identifier: GPL-2.0

//! Peer management and AllowedIPs routing.
//!
//! Each peer holds transport sessions, timer state, and endpoint info.
//! Peer lookup happens on two paths:
//!   - TX (outgoing): AllowedIPs trie lookup by destination IP
//!   - RX (incoming): sender_index hashtable lookup from packet header
//!
//! The AllowedIPs trie is the same compact radix trie used in the C WireGuard
//! implementation. It maps IP prefixes to peers for routing decisions.

use kernel::prelude::*;

/// A WireGuard peer.
pub(crate) struct WgPeer {
    /// Peer's static public key.
    pub(crate) public_key: [u8; 32],
    /// Pre-shared key (all zeros if not configured).
    pub(crate) psk: [u8; 32],
    /// Current endpoint (IP + port). Updated on authenticated packets.
    pub(crate) endpoint: Option<Endpoint>,
    /// Persistent keepalive interval (0 = disabled).
    pub(crate) keepalive_secs: u16,
    // TODO: TransportSession (current + previous + next)
    // TODO: SessionTimers
    // TODO: CookieState
    // TODO: TX queue (packets waiting for handshake completion)
    // TODO: RX counter for last handshake timestamp
}

/// Peer endpoint — where to send encrypted packets.
pub(crate) struct Endpoint {
    pub(crate) addr: [u8; 16], // IPv4 (4 bytes) or IPv6 (16 bytes)
    pub(crate) port: u16,
    pub(crate) is_v6: bool,
}

// TODO: AllowedIPs trie
//
// This is a compressed radix trie (LC-trie) that maps IP/prefix to peer.
// The kernel WireGuard uses a custom implementation in allowedips.c.
// We'll implement the same data structure in safe Rust:
//
// struct AllowedIps {
//     root4: Option<Box<TrieNode>>,
//     root6: Option<Box<TrieNode>>,
// }
//
// struct TrieNode {
//     bit: u8,          // bit position to test
//     cidr: u8,         // prefix length (0 = intermediate)
//     peer: Option<*const WgPeer>,
//     children: [Option<Box<TrieNode>>; 2],
// }
//
// lookup(ip) -> Option<&WgPeer>: walk the trie, return longest prefix match
// insert(ip, cidr, peer): add a route
// remove_by_peer(peer): remove all entries for a peer

// TODO: Index hashtable
//
// Maps sender_index (u32) -> &WgPeer for fast RX path lookup.
// The sender_index is in every transport packet header, so this
// lookup happens on every incoming data packet.
//
// Simple open-addressing hashtable, 65536 buckets.
// Collision resolution: linear probing (entries are sparse).
