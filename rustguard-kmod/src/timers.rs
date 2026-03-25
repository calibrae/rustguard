// SPDX-License-Identifier: GPL-2.0

//! WireGuard timer state machine.
//!
//! Tracks session lifecycle: when to rekey, when to send keepalives,
//! when to expire sessions. Uses nanosecond timestamps from the kernel
//! monotonic clock (ktime_get_ns).
//!
//! Timer constants from the WireGuard whitepaper, section 6.

/// Rekey after 120 seconds.
const REKEY_AFTER_TIME_NS: u64 = 120 * 1_000_000_000;
/// Reject sessions older than 180 seconds.
const REJECT_AFTER_TIME_NS: u64 = 180 * 1_000_000_000;
/// Retry handshake after 5 seconds.
const REKEY_TIMEOUT_NS: u64 = 5 * 1_000_000_000;
/// Give up on handshake after 90 seconds.
const REKEY_ATTEMPT_TIME_NS: u64 = 90 * 1_000_000_000;
/// Zero session keys after 240 seconds of inactivity.
const DEAD_SESSION_TIMEOUT_NS: u64 = 240 * 1_000_000_000;

/// Rekey after this many messages.
const REKEY_AFTER_MESSAGES: u64 = (1u64 << 60) - 1;
/// Reject after this many messages.
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

extern "C" {
    fn wg_ktime_get_ns() -> u64;
}

fn now_ns() -> u64 {
    unsafe { wg_ktime_get_ns() }
}

/// Per-peer timer state.
pub(crate) struct SessionTimers {
    /// When the current session was established (0 = no session).
    pub(crate) session_established: u64,
    /// When the last handshake initiation was sent (0 = never).
    pub(crate) last_handshake_sent: u64,
    /// When we last received a valid authenticated packet.
    pub(crate) last_received: u64,
    /// When we last sent a packet.
    pub(crate) last_sent: u64,
    /// Whether we've already initiated a rekey for the current session.
    pub(crate) rekey_requested: bool,
    /// Keepalive interval in nanoseconds (0 = disabled).
    pub(crate) keepalive_interval_ns: u64,
}

impl SessionTimers {
    pub(crate) fn new() -> Self {
        Self {
            session_established: 0,
            last_handshake_sent: 0,
            last_received: 0,
            last_sent: 0,
            rekey_requested: false,
            keepalive_interval_ns: 0,
        }
    }

    /// Record that a new session was established.
    pub(crate) fn session_started(&mut self) {
        let now = now_ns();
        self.session_established = now;
        self.last_received = now;
        self.rekey_requested = false;
    }

    /// Record that we sent a packet.
    pub(crate) fn packet_sent(&mut self) {
        self.last_sent = now_ns();
    }

    /// Record that we received a valid packet.
    pub(crate) fn packet_received(&mut self) {
        self.last_received = now_ns();
    }

    /// Whether the session needs rekeying (time or message count).
    pub(crate) fn needs_rekey(&self, send_counter: u64) -> bool {
        if self.rekey_requested {
            return false;
        }
        if send_counter >= REKEY_AFTER_MESSAGES {
            return true;
        }
        if self.session_established > 0 {
            return now_ns().saturating_sub(self.session_established) >= REKEY_AFTER_TIME_NS;
        }
        false
    }

    /// Whether the session is too old to use for sending.
    pub(crate) fn is_expired(&self, send_counter: u64) -> bool {
        if send_counter >= REJECT_AFTER_MESSAGES {
            return true;
        }
        if self.session_established > 0 {
            return now_ns().saturating_sub(self.session_established) >= REJECT_AFTER_TIME_NS;
        }
        true
    }

    /// Whether the session should be zeroed (dead).
    pub(crate) fn is_dead(&self) -> bool {
        if self.session_established > 0 {
            return now_ns().saturating_sub(self.session_established) >= DEAD_SESSION_TIMEOUT_NS;
        }
        false
    }

    /// Whether we should send a keepalive.
    pub(crate) fn needs_keepalive(&self) -> bool {
        if self.keepalive_interval_ns == 0 {
            return false;
        }
        let now = now_ns();
        if self.last_received > 0 {
            let since_last_send = if self.last_sent > 0 {
                now.saturating_sub(self.last_sent)
            } else {
                now.saturating_sub(self.last_received)
            };
            let since_last_recv = now.saturating_sub(self.last_received);
            return since_last_send >= self.keepalive_interval_ns
                && since_last_recv < self.keepalive_interval_ns;
        }
        false
    }

    /// Whether we should retry the handshake.
    pub(crate) fn should_retry_handshake(&self) -> bool {
        if self.last_handshake_sent > 0 {
            return now_ns().saturating_sub(self.last_handshake_sent) >= REKEY_TIMEOUT_NS;
        }
        true
    }

    /// Whether we should give up on the handshake.
    pub(crate) fn handshake_timed_out(&self) -> bool {
        if self.last_handshake_sent > 0 {
            return now_ns().saturating_sub(self.last_handshake_sent) >= REKEY_ATTEMPT_TIME_NS;
        }
        false
    }

    /// Mark that we sent a handshake initiation.
    pub(crate) fn handshake_sent(&mut self) {
        self.last_handshake_sent = now_ns();
        self.rekey_requested = true;
    }
}
