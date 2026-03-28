//! WireGuard cookie mechanism for DoS protection.
//!
//! Under load, the responder can require proof that the initiator
//! can receive packets at its claimed IP. The flow:
//!
//! 1. Initiator sends handshake with MAC2 = zeros (no cookie yet)
//! 2. Responder is under load, sends Cookie Reply instead of processing
//! 3. Initiator decrypts cookie, stores it
//! 4. Initiator resends handshake with MAC2 = MAC(cookie, msg || mac1)
//! 5. Responder verifies MAC2 and processes the handshake
//!
//! The cookie is MAC(secret, sender_ip_port), where secret rotates every 2 min.

use core::time::Duration;

use rustguard_crypto::{self as crypto, PublicKey, LABEL_COOKIE, LABEL_MAC1};

use crate::messages::CookieReply;

/// How often the cookie secret rotates.
const COOKIE_SECRET_LIFETIME: Duration = Duration::from_secs(120);

/// Cookie size.
pub const COOKIE_LEN: usize = 16;

/// Monotonic timestamp type — same abstraction as timers.rs.
#[cfg(feature = "std")]
type Timestamp = std::time::Instant;
#[cfg(not(feature = "std"))]
type Timestamp = u64;

#[cfg(feature = "std")]
fn now() -> Timestamp {
    std::time::Instant::now()
}

#[cfg(feature = "std")]
fn elapsed_since(ts: Timestamp) -> Duration {
    ts.elapsed()
}

#[cfg(not(feature = "std"))]
static NO_STD_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(not(feature = "std"))]
fn now() -> Timestamp {
    NO_STD_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(feature = "std"))]
fn elapsed_since(_ts: Timestamp) -> Duration {
    // no_std: no real clock available. Return ZERO — the kernel module
    // uses its own cookie checker with real timekeeping.
    Duration::ZERO
}

/// Server-side cookie state: generates cookies and validates MAC2.
pub struct CookieChecker {
    /// Our static public key (used to derive encryption key).
    our_public: PublicKey,
    /// Rotating secret for cookie generation.
    secret: [u8; 32],
    /// When the secret was last generated.
    secret_generated: Timestamp,
    /// Whether we're "under load" and should require cookies.
    pub under_load: bool,
}

/// Client-side cookie state: stores a received cookie for MAC2.
pub struct CookieState {
    /// The decrypted cookie, if we have one.
    cookie: Option<[u8; COOKIE_LEN]>,
    /// When we received the cookie.
    received: Option<Timestamp>,
}

impl CookieChecker {
    #[cfg(feature = "std")]
    pub fn new(our_public: PublicKey) -> Self {
        Self {
            our_public,
            secret: random_bytes(),
            secret_generated: now(),
            under_load: false,
        }
    }

    /// Create a checker with an explicit initial secret and timestamp (no_std / kernel).
    pub fn new_with(our_public: PublicKey, secret: [u8; 32], now_ts: Timestamp) -> Self {
        Self {
            our_public,
            secret,
            secret_generated: now_ts,
            under_load: false,
        }
    }

    /// Rotate the secret if it's stale.
    fn maybe_rotate_secret(&mut self) {
        if elapsed_since(self.secret_generated) >= COOKIE_SECRET_LIFETIME {
            self.secret = random_bytes();
            #[cfg(feature = "std")]
            { self.secret_generated = now(); }
        }
    }

    /// Generate a cookie for pre-encoded source address bytes.
    /// Address encoding: IPv4 = 4 bytes IP + 2 bytes port (6 total).
    ///                   IPv6 = 16 bytes IP + 2 bytes port (18 total).
    fn make_cookie_from_bytes(&mut self, addr_bytes: &[u8]) -> [u8; COOKIE_LEN] {
        self.maybe_rotate_secret();
        let full = crypto::mac(&self.secret, &[addr_bytes]);
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&full[..COOKIE_LEN]);
        cookie
    }

    /// Build a Cookie Reply message from pre-encoded address bytes.
    pub fn create_reply_from_bytes(
        &mut self,
        receiver_index: u32,
        mac1: &[u8; 16],
        addr_bytes: &[u8],
    ) -> CookieReply {
        let cookie = self.make_cookie_from_bytes(addr_bytes);
        let key = crypto::hash(&[LABEL_COOKIE, self.our_public.as_ref()]);
        let nonce = random_nonce();
        let encrypted = crypto::xseal(&key, &nonce, mac1, &cookie);

        CookieReply {
            receiver_index,
            nonce,
            encrypted_cookie: encrypted.try_into().expect("cookie + tag = 32 bytes"),
        }
    }

    /// Build a Cookie Reply message for a SocketAddr (std convenience).
    #[cfg(feature = "std")]
    pub fn create_reply(
        &mut self,
        receiver_index: u32,
        mac1: &[u8; 16],
        src: &std::net::SocketAddr,
    ) -> CookieReply {
        let addr_bytes = encode_addr(src);
        self.create_reply_from_bytes(receiver_index, mac1, &addr_bytes)
    }

    /// Verify MAC1 on an incoming message.
    pub fn verify_mac1(&self, msg_bytes: &[u8], mac1: &[u8; 16]) -> bool {
        let key = crypto::hash(&[LABEL_MAC1, self.our_public.as_ref()]);
        let expected = crypto::mac(&key, &[msg_bytes]);
        constant_time_eq_16(mac1, &expected[..16])
    }

    /// Verify MAC2 from pre-encoded address bytes.
    pub fn verify_mac2_from_bytes(
        &mut self,
        msg_with_mac1: &[u8],
        mac2: &[u8; 16],
        addr_bytes: &[u8],
    ) -> bool {
        let cookie = self.make_cookie_from_bytes(addr_bytes);
        let expected = crypto::mac(&cookie, &[msg_with_mac1]);
        constant_time_eq_16(mac2, &expected[..16])
    }

    /// Verify MAC2 on an incoming message (std convenience).
    #[cfg(feature = "std")]
    pub fn verify_mac2(
        &mut self,
        msg_with_mac1: &[u8],
        mac2: &[u8; 16],
        src: &std::net::SocketAddr,
    ) -> bool {
        let addr_bytes = encode_addr(src);
        self.verify_mac2_from_bytes(msg_with_mac1, mac2, &addr_bytes)
    }
}

impl CookieState {
    pub fn new() -> Self {
        Self {
            cookie: None,
            received: None,
        }
    }

    /// Process a Cookie Reply and store the decrypted cookie.
    ///
    /// `their_public`: the responder's public key.
    /// `mac1`: our MAC1 from the original message.
    pub fn process_reply(
        &mut self,
        reply: &CookieReply,
        their_public: &PublicKey,
        mac1: &[u8; 16],
    ) -> bool {
        let key = crypto::hash(&[LABEL_COOKIE, their_public.as_ref()]);
        match crypto::xopen(&key, &reply.nonce, mac1, &reply.encrypted_cookie) {
            Some(plaintext) if plaintext.len() == COOKIE_LEN => {
                let mut cookie = [0u8; COOKIE_LEN];
                cookie.copy_from_slice(&plaintext);
                self.cookie = Some(cookie);
                self.received = Some(now());
                true
            }
            _ => false,
        }
    }

    /// Compute MAC2 using our stored cookie. Returns zeros if no cookie.
    pub fn compute_mac2(&self, msg_with_mac1: &[u8]) -> [u8; 16] {
        match &self.cookie {
            Some(cookie) if self.is_fresh() => {
                let full = crypto::mac(cookie, &[msg_with_mac1]);
                let mut mac2 = [0u8; 16];
                mac2.copy_from_slice(&full[..16]);
                mac2
            }
            _ => [0u8; 16],
        }
    }

    /// Cookie is fresh if received within the last 120 seconds.
    fn is_fresh(&self) -> bool {
        match self.received {
            Some(ts) => elapsed_since(ts) < COOKIE_SECRET_LIFETIME,
            None => false,
        }
    }
}

/// Encode a socket address to bytes for cookie MAC.
#[cfg(feature = "std")]
fn encode_addr(addr: &std::net::SocketAddr) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    match addr {
        std::net::SocketAddr::V4(a) => {
            let mut buf = Vec::with_capacity(6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
        std::net::SocketAddr::V6(a) => {
            let mut buf = Vec::with_capacity(18);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
    }
}

fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    fill_random(&mut buf);
    buf
}

fn random_nonce() -> [u8; 24] {
    let mut buf = [0u8; 24];
    fill_random(&mut buf);
    buf
}

/// Fill a buffer with cryptographically secure random bytes.
/// On std, uses getrandom. On no_std, this is a stub — kernel module
/// must provide its own RNG via get_random_bytes().
#[cfg(feature = "std")]
fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("failed to get random bytes");
}

#[cfg(not(feature = "std"))]
fn fill_random(buf: &mut [u8]) {
    // no_std stub: use an atomic counter to produce unique (not random) bytes.
    // This prevents nonce reuse — each call gets a different value.
    // In practice, the kernel module overrides cookie logic with get_random_bytes().
    static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    let val = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // Fill buffer with counter bytes, repeating as needed.
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = (val >> ((i % 8) * 8)) as u8;
        // Mix in position to avoid identical chunks within a single fill.
        *byte ^= i as u8;
    }
}

fn constant_time_eq_16(a: &[u8; 16], b: &[u8]) -> bool {
    if b.len() < 16 {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(&b[..16]).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustguard_crypto::StaticSecret;

    fn setup() -> (CookieChecker, CookieState, PublicKey) {
        let secret = StaticSecret::random();
        let public = secret.public_key();
        let checker = CookieChecker::new(public.clone());
        let state = CookieState::new();
        (checker, state, public)
    }

    #[test]
    fn cookie_roundtrip() {
        let (mut checker, mut state, public) = setup();
        let src: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];

        let reply = checker.create_reply(1, &mac1, &src);
        assert!(state.process_reply(&reply, &public, &mac1));
        assert!(state.cookie.is_some());
    }

    #[test]
    fn wrong_mac1_fails_decrypt() {
        let (mut checker, mut state, public) = setup();
        let src: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];
        let wrong_mac1 = [0x43u8; 16];

        let reply = checker.create_reply(1, &mac1, &src);
        assert!(!state.process_reply(&reply, &public, &wrong_mac1));
    }

    #[test]
    fn mac2_verified_after_cookie() {
        let (mut checker, mut state, public) = setup();
        let src: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];

        // Get a cookie.
        let reply = checker.create_reply(1, &mac1, &src);
        state.process_reply(&reply, &public, &mac1);

        // Compute MAC2 with the cookie.
        let msg = b"some message with mac1 appended";
        let mac2 = state.compute_mac2(msg);
        assert_ne!(mac2, [0u8; 16]); // Should not be zeros.

        // Verify MAC2.
        assert!(checker.verify_mac2(msg, &mac2, &src));
    }

    #[test]
    fn mac2_wrong_source_fails() {
        let (mut checker, mut state, public) = setup();
        let src: std::net::SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let wrong_src: std::net::SocketAddr = "10.0.0.2:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];

        let reply = checker.create_reply(1, &mac1, &src);
        state.process_reply(&reply, &public, &mac1);

        let msg = b"message";
        let mac2 = state.compute_mac2(msg);

        // Different source should fail.
        assert!(!checker.verify_mac2(msg, &mac2, &wrong_src));
    }

    #[test]
    fn no_cookie_gives_zero_mac2() {
        let state = CookieState::new();
        let mac2 = state.compute_mac2(b"anything");
        assert_eq!(mac2, [0u8; 16]);
    }
}
