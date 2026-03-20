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

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustguard_crypto::{self as crypto, PublicKey, LABEL_COOKIE, LABEL_MAC1};

use crate::messages::{CookieReply, MSG_COOKIE_REPLY};

/// How often the cookie secret rotates.
const COOKIE_SECRET_LIFETIME: Duration = Duration::from_secs(120);

/// Cookie size.
pub const COOKIE_LEN: usize = 16;

/// Server-side cookie state: generates cookies and validates MAC2.
pub struct CookieChecker {
    /// Our static public key (used to derive encryption key).
    our_public: PublicKey,
    /// Rotating secret for cookie generation.
    secret: [u8; 32],
    /// When the secret was last generated.
    secret_generated: Instant,
    /// Whether we're "under load" and should require cookies.
    pub under_load: bool,
}

/// Client-side cookie state: stores a received cookie for MAC2.
pub struct CookieState {
    /// The decrypted cookie, if we have one.
    cookie: Option<[u8; COOKIE_LEN]>,
    /// When we received the cookie.
    received: Option<Instant>,
}

impl CookieChecker {
    pub fn new(our_public: PublicKey) -> Self {
        Self {
            our_public,
            secret: random_bytes(),
            secret_generated: Instant::now(),
            under_load: false,
        }
    }

    /// Rotate the secret if it's stale.
    fn maybe_rotate_secret(&mut self) {
        if self.secret_generated.elapsed() >= COOKIE_SECRET_LIFETIME {
            self.secret = random_bytes();
            self.secret_generated = Instant::now();
        }
    }

    /// Generate a cookie for a given source address.
    fn make_cookie(&mut self, src: &SocketAddr) -> [u8; COOKIE_LEN] {
        self.maybe_rotate_secret();
        let addr_bytes = encode_addr(src);
        let full = crypto::mac(&self.secret, &[&addr_bytes]);
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&full[..COOKIE_LEN]);
        cookie
    }

    /// Build a Cookie Reply message to send back to an initiator.
    ///
    /// `receiver_index`: the sender_index from the received initiation.
    /// `mac1`: the MAC1 from the received message (used as AAD).
    /// `src`: the source address of the initiator.
    pub fn create_reply(
        &mut self,
        receiver_index: u32,
        mac1: &[u8; 16],
        src: &SocketAddr,
    ) -> CookieReply {
        let cookie = self.make_cookie(src);
        let key = crypto::hash(&[LABEL_COOKIE, self.our_public.as_ref()]);
        let nonce = random_nonce();
        let encrypted = crypto::xseal(&key, &nonce, mac1, &cookie);

        CookieReply {
            receiver_index,
            nonce,
            encrypted_cookie: encrypted.try_into().expect("cookie + tag = 32 bytes"),
        }
    }

    /// Verify MAC1 on an incoming message.
    pub fn verify_mac1(&self, msg_bytes: &[u8], mac1: &[u8; 16]) -> bool {
        let key = crypto::hash(&[LABEL_MAC1, self.our_public.as_ref()]);
        let expected = crypto::mac(&key, &[msg_bytes]);
        constant_time_eq_16(mac1, &expected[..16])
    }

    /// Verify MAC2 on an incoming message (when under load).
    pub fn verify_mac2(
        &mut self,
        msg_with_mac1: &[u8],
        mac2: &[u8; 16],
        src: &SocketAddr,
    ) -> bool {
        let cookie = self.make_cookie(src);
        let expected = crypto::mac(&cookie, &[msg_with_mac1]);
        constant_time_eq_16(mac2, &expected[..16])
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
                self.received = Some(Instant::now());
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
        self.received
            .is_some_and(|t| t.elapsed() < COOKIE_SECRET_LIFETIME)
    }
}

/// Encode a socket address to bytes for cookie MAC.
fn encode_addr(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut buf = Vec::with_capacity(6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
        SocketAddr::V6(a) => {
            let mut buf = Vec::with_capacity(18);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf
        }
    }
}

fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    read_random(&mut buf);
    buf
}

fn random_nonce() -> [u8; 24] {
    let mut buf = [0u8; 24];
    read_random(&mut buf);
    buf
}

fn read_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("failed to get random bytes");
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
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];

        let reply = checker.create_reply(1, &mac1, &src);
        assert!(state.process_reply(&reply, &public, &mac1));
        assert!(state.cookie.is_some());
    }

    #[test]
    fn wrong_mac1_fails_decrypt() {
        let (mut checker, mut state, public) = setup();
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let mac1 = [0x42u8; 16];
        let wrong_mac1 = [0x43u8; 16];

        let reply = checker.create_reply(1, &mac1, &src);
        assert!(!state.process_reply(&reply, &public, &wrong_mac1));
    }

    #[test]
    fn mac2_verified_after_cookie() {
        let (mut checker, mut state, public) = setup();
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
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
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let wrong_src: SocketAddr = "10.0.0.2:12345".parse().unwrap();
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
