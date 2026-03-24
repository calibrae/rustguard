// SPDX-License-Identifier: GPL-2.0

//! RustGuard — WireGuard kernel module in Rust.
//!
//! Registers a virtual network device (wg%d) and handles WireGuard packet
//! encrypt/decrypt directly in the network stack.
//!
//! The C shim (wg_net.c) handles net_device registration and sk_buff plumbing.
//! This side handles the WireGuard protocol: handshake, transport crypto, timers.

use kernel::prelude::*;

module! {
    type: RustGuard,
    name: "rustguard",
    author: "cali",
    description: "WireGuard VPN — Rust implementation",
    license: "GPL",
}

// FFI declarations for the C shim functions.
extern "C" {
    fn wg_create_device(rust_priv: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn wg_destroy_device(dev: *mut core::ffi::c_void);
    fn wg_kfree_skb(skb: *mut core::ffi::c_void);
}

struct RustGuard {
    /// Opaque pointer to the C net_device. Null if not created.
    net_dev: *mut core::ffi::c_void,
}

// SAFETY: net_dev pointer is only accessed during init/drop (single-threaded).
unsafe impl Send for RustGuard {}
unsafe impl Sync for RustGuard {}

impl kernel::Module for RustGuard {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("rustguard: initializing\n");

        // We pass a null rust_priv for now — the xmit callback will just drop packets.
        // TODO: allocate per-device state (peer table, keys, etc.)
        let dev = unsafe { wg_create_device(core::ptr::null_mut()) };

        // wg_create_device returns ERR_PTR on failure (negative value).
        if dev.is_null() || (dev as isize) < 0 {
            pr_err!("rustguard: failed to create net device\n");
            return Err(ENOMEM);
        }

        pr_info!("rustguard: device created\n");
        Ok(RustGuard { net_dev: dev })
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
        if !self.net_dev.is_null() {
            unsafe { wg_destroy_device(self.net_dev) };
        }
        pr_info!("rustguard: unloaded\n");
    }
}

/// Called by the C shim when a packet arrives on the wg interface for transmission.
/// This is ndo_start_xmit — the hot path.
///
/// # Safety
/// Called from C with a valid sk_buff pointer and our rust_priv pointer.
#[no_mangle]
pub extern "C" fn rustguard_xmit(
    skb: *mut core::ffi::c_void,
    _priv: *mut core::ffi::c_void,
) -> i32 {
    // For now: drop the packet.
    // TODO: look up peer by destination IP, encrypt, send via UDP socket.
    unsafe { wg_kfree_skb(skb) };

    // NETDEV_TX_OK = 0
    0
}

/// Called by the C shim when the device is being torn down.
///
/// # Safety
/// Called from C with our rust_priv pointer.
#[no_mangle]
pub extern "C" fn rustguard_dev_uninit(_priv: *mut core::ffi::c_void) {}
