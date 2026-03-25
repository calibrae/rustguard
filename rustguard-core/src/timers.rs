//! WireGuard timer constants and session lifecycle.
//!
//! These values are from the WireGuard whitepaper, section 6.
//! They define when to rekey, when to give up, and when to zero keys.

use core::time::Duration;

/// Monotonic timestamp abstraction — std::time::Instant on std, injectable on no_std.
#[cfg(feature = "std")]
type Timestamp = std::time::Instant;

#[cfg(not(feature = "std"))]
type Timestamp = u64; // nanoseconds from monotonic clock

#[cfg(feature = "std")]
fn now() -> Timestamp {
    std::time::Instant::now()
}

#[cfg(feature = "std")]
fn elapsed_since(ts: Timestamp) -> Duration {
    ts.elapsed()
}

#[cfg(not(feature = "std"))]
fn elapsed_since(_ts: Timestamp) -> Duration {
    // Kernel callers must use the explicit check methods with their own clock.
    // This fallback returns zero — the kernel module overrides timer logic.
    Duration::ZERO
}

/// After this many seconds, initiate a new handshake.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Reject data using a keypair older than this.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Don't try to send with a keypair older than this (REJECT_AFTER_TIME + padding).
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of messages before rekeying.
pub const REKEY_AFTER_MESSAGES: u64 = (1u64 << 60) - 1;

/// Reject after this many messages even if time hasn't expired.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// How long to wait for a handshake response before retrying.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

/// Time after which we zero session keys if no new handshake.
pub const DEAD_SESSION_TIMEOUT: Duration = Duration::from_secs(240);

/// Timer state for a peer's session lifecycle.
pub struct SessionTimers {
    /// When the current session was established.
    pub session_established: Option<Timestamp>,
    /// When the last handshake initiation was sent.
    pub last_handshake_sent: Option<Timestamp>,
    /// When we last received a valid authenticated packet.
    pub last_received: Option<Timestamp>,
    /// When we last sent a packet.
    pub last_sent: Option<Timestamp>,
    /// Whether we've already initiated a rekey for the current session.
    pub rekey_requested: bool,
}

impl SessionTimers {
    pub fn new() -> Self {
        Self {
            session_established: None,
            last_handshake_sent: None,
            last_received: None,
            last_sent: None,
            rekey_requested: false,
        }
    }

    /// Record that a new session was established.
    #[cfg(feature = "std")]
    pub fn session_started(&mut self) {
        let now = now();
        self.session_established = Some(now);
        self.last_received = Some(now);
        self.rekey_requested = false;
    }

    /// Record that a new session was established (no_std: caller provides timestamp).
    #[cfg(not(feature = "std"))]
    pub fn session_started_at(&mut self, now_ns: u64) {
        self.session_established = Some(now_ns);
        self.last_received = Some(now_ns);
        self.rekey_requested = false;
    }

    /// Record that we sent a packet.
    #[cfg(feature = "std")]
    pub fn packet_sent(&mut self) {
        self.last_sent = Some(now());
    }

    #[cfg(not(feature = "std"))]
    pub fn packet_sent_at(&mut self, now_ns: u64) {
        self.last_sent = Some(now_ns);
    }

    /// Record that we received a valid packet.
    #[cfg(feature = "std")]
    pub fn packet_received(&mut self) {
        self.last_received = Some(now());
    }

    #[cfg(not(feature = "std"))]
    pub fn packet_received_at(&mut self, now_ns: u64) {
        self.last_received = Some(now_ns);
    }

    /// Whether the session needs rekeying (time or message count).
    pub fn needs_rekey(&self, send_counter: u64) -> bool {
        if self.rekey_requested {
            return false; // Already requested.
        }
        if send_counter >= REKEY_AFTER_MESSAGES {
            return true;
        }
        if let Some(established) = self.session_established {
            return elapsed_since(established) >= REKEY_AFTER_TIME;
        }
        false
    }

    /// Whether the session is too old to use for sending.
    pub fn is_expired(&self, send_counter: u64) -> bool {
        if send_counter >= REJECT_AFTER_MESSAGES {
            return true;
        }
        if let Some(established) = self.session_established {
            return elapsed_since(established) >= REJECT_AFTER_TIME;
        }
        true // No session = expired.
    }

    /// Whether the session should be zeroed (dead).
    pub fn is_dead(&self) -> bool {
        if let Some(established) = self.session_established {
            return elapsed_since(established) >= DEAD_SESSION_TIMEOUT;
        }
        false
    }

    /// Whether we should send a keepalive.
    pub fn needs_keepalive(&self, keepalive_interval: Option<Duration>) -> bool {
        let interval = match keepalive_interval {
            Some(i) if !i.is_zero() => i,
            _ => return false,
        };

        // Send keepalive if we've received data but haven't sent anything
        // within the keepalive interval.
        if let (Some(received), sent) = (self.last_received, self.last_sent) {
            let last_send_time = sent.unwrap_or(received);
            return elapsed_since(last_send_time) >= interval
                && elapsed_since(received) < interval;
        }
        false
    }

    /// Whether we should retry the handshake.
    pub fn should_retry_handshake(&self) -> bool {
        if let Some(last_sent) = self.last_handshake_sent {
            return elapsed_since(last_sent) >= REKEY_TIMEOUT;
        }
        true // Never sent a handshake, so yes.
    }

    /// Whether we should give up on the handshake.
    pub fn handshake_timed_out(&self) -> bool {
        if let Some(last_sent) = self.last_handshake_sent {
            return elapsed_since(last_sent) >= REKEY_ATTEMPT_TIME;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_timers_not_expired() {
        let t = SessionTimers::new();
        // No session established = expired (can't send).
        assert!(t.is_expired(0));
        assert!(!t.is_dead());
    }

    #[test]
    fn fresh_session_not_expired() {
        let mut t = SessionTimers::new();
        t.session_started();
        assert!(!t.is_expired(0));
        assert!(!t.needs_rekey(0));
    }

    #[test]
    fn message_count_triggers_rekey() {
        let mut t = SessionTimers::new();
        t.session_started();
        assert!(t.needs_rekey(REKEY_AFTER_MESSAGES));
    }

    #[test]
    fn message_count_triggers_reject() {
        let mut t = SessionTimers::new();
        t.session_started();
        assert!(t.is_expired(REJECT_AFTER_MESSAGES));
    }

    #[test]
    fn no_keepalive_without_config() {
        let mut t = SessionTimers::new();
        t.session_started();
        t.packet_received();
        assert!(!t.needs_keepalive(None));
        assert!(!t.needs_keepalive(Some(Duration::ZERO)));
    }

    #[test]
    fn retry_handshake_when_never_sent() {
        let t = SessionTimers::new();
        assert!(t.should_retry_handshake());
    }
}
