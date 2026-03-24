// SPDX-License-Identifier: GPL-2.0

//! WireGuard virtual network device.
//!
//! Registers a net_device with the kernel. Implements ndo_start_xmit for
//! outgoing packets (encrypt + UDP send) and handles incoming packets from
//! the UDP socket (decrypt + netif_rx).
//!
//! This is where TUN overhead disappears — packets flow directly through
//! sk_buffs without crossing the kernel/userspace boundary.

use kernel::prelude::*;

/// WireGuard device private data.
///
/// Attached to each `wg%d` interface. Holds peer table, crypto sessions,
/// UDP socket, and timer state.
pub(crate) struct WgDevice {
    /// Listen port for incoming WireGuard packets.
    pub(crate) listen_port: u16,
    /// Private key for this device.
    pub(crate) private_key: [u8; 32],
    // TODO: peer table (AllowedIPs trie + hash by public key)
    // TODO: UDP socket (kernel sock)
    // TODO: index hashtable (sender_index -> peer)
}

impl WgDevice {
    pub(crate) fn new(listen_port: u16, private_key: [u8; 32]) -> Self {
        Self {
            listen_port,
            private_key,
        }
    }
}

// TODO: Implement net_device_ops:
//
// ndo_open          — bind UDP socket, start listening
// ndo_stop          — unbind, flush queues
// ndo_start_xmit    — lookup peer by AllowedIPs, encrypt, send UDP
//                     This is the hot path. sk_buff in, UDP packet out.
//                     No memcpy to userspace. No TUN fd. Just encrypt and go.
// ndo_get_stats64   — traffic counters
//
// The device MTU defaults to 1420 (1500 - 80 byte WireGuard overhead).
//
// Registration flow:
// 1. alloc_netdev() with sizeof(WgDevice) as priv
// 2. Set dev->netdev_ops = &wg_netdev_ops
// 3. Set dev->type = ARPHRD_NONE, dev->flags = IFF_POINTOPOINT | IFF_NOARP
// 4. register_netdev()
//
// For kernel 6.10+ Rust bindings, we may use the kernel::net::Device abstraction
// if available, or raw bindings::* calls.
