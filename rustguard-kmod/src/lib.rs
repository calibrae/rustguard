// SPDX-License-Identifier: GPL-2.0

//! RustGuard — WireGuard kernel module in Rust.
//!
//! This is the kernel-side implementation. It registers a virtual network device
//! and handles WireGuard packet encrypt/decrypt directly in the network stack,
//! bypassing the TUN overhead that limits userspace implementations.

use kernel::prelude::*;

module! {
    type: RustGuard,
    name: "rustguard",
    author: "cali",
    description: "WireGuard VPN — Rust implementation",
    license: "GPL",
}

struct RustGuard;

impl kernel::Module for RustGuard {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("rustguard: loaded\n");
        Ok(RustGuard)
    }
}

impl Drop for RustGuard {
    fn drop(&mut self) {
        pr_info!("rustguard: unloaded\n");
    }
}
