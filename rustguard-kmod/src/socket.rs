// SPDX-License-Identifier: GPL-2.0

//! Kernel UDP socket for WireGuard packet I/O.
//!
//! Creates a kernel-space UDP socket bound to the listen port.
//! Outgoing encrypted packets are sent directly via kernel_sendmsg().
//! Incoming packets arrive via udp_encap_rcv callback — no poll, no syscall.

use kernel::prelude::*;

/// Kernel UDP socket wrapper.
///
/// Manages the UDP socket lifecycle and provides send/receive operations
/// for encrypted WireGuard packets.
pub(crate) struct WgSocket {
    /// Listen port.
    pub(crate) port: u16,
    // TODO: sock *socket (kernel socket struct)
    // TODO: IPv4 and IPv6 sockets
}

impl WgSocket {
    pub(crate) fn new(port: u16) -> Self {
        Self { port }
    }
}

// TODO: Implementation plan:
//
// bind():
//   sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
//   kernel_bind() to 0.0.0.0:port
//   Set udp_encap_type = UDP_ENCAP_ESPINUDP (or custom)
//   Set encap_rcv callback to our rx handler
//
// send(dst_addr, data):
//   kernel_sendmsg() with msghdr pointing to the encrypted packet
//   Zero-copy where possible via skb_put_data
//
// rx_handler(sk_buff):
//   Parse WireGuard message type from first 4 bytes
//   Dispatch to handshake or transport handler
//   For transport: decrypt in-place in the sk_buff, inject via netif_rx()
//
// close():
//   sock_release()
