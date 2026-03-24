// SPDX-License-Identifier: GPL-2.0

//! Kernel time adapters.
//!
//! Provides wall-clock timestamps (for TAI64N in handshakes) and monotonic
//! timestamps (for timer state machine) using kernel clock sources.

use kernel::prelude::*;

/// Get the current wall-clock time as (unix_seconds, nanoseconds).
///
/// Used to construct TAI64N timestamps for handshake initiation.
/// Calls ktime_get_real_ts64() — the kernel's CLOCK_REALTIME equivalent.
pub(crate) fn wall_clock_unix() -> (u64, u32) {
    let mut ts = kernel::bindings::timespec64 {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ktime_get_real_ts64 writes to a valid timespec64 pointer.
    unsafe {
        kernel::bindings::ktime_get_real_ts64(&mut ts);
    }
    (ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Get a monotonic nanosecond timestamp.
///
/// Used for session timers (rekey, keepalive, expiry).
/// Calls ktime_get_ns() — never goes backward, unaffected by NTP.
pub(crate) fn monotonic_ns() -> u64 {
    // SAFETY: ktime_get_ns() is always safe to call, returns a u64.
    unsafe { kernel::bindings::ktime_get_ns() }
}
