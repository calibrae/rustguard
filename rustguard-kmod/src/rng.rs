// SPDX-License-Identifier: GPL-2.0

//! Kernel RNG adapter.
//!
//! Implements rand_core::CryptoRngCore backed by the kernel's get_random_bytes().
//! Used by the handshake code to generate ephemeral keys without OsRng.

use kernel::prelude::*;

/// Kernel cryptographic RNG.
///
/// Wraps the kernel's get_random_bytes() as a rand_core-compatible RNG source.
/// This is used to generate ephemeral DH keys and random nonces in kernel context.
pub(crate) struct KernelRng;

impl KernelRng {
    /// Fill a buffer with random bytes from the kernel CSPRNG.
    pub(crate) fn fill(buf: &mut [u8]) {
        // SAFETY: get_random_bytes writes exactly buf.len() bytes to buf.ptr.
        // The buffer is valid, mutable, and correctly sized.
        unsafe {
            kernel::bindings::get_random_bytes(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len() as core::ffi::c_int,
            );
        }
    }
}

// TODO: impl rand_core::CryptoRngCore for KernelRng
// This requires bringing rand_core into the Kbuild dependency chain,
// which is non-trivial. For now, the handshake functions accept
// EphemeralSecret directly — the caller generates it via KernelRng::fill()
// and StaticSecret::from_bytes().
