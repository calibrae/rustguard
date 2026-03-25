// SPDX-License-Identifier: GPL-2.0

//! WireGuard cookie mechanism for DoS protection.
//!
//! Under load, the responder requires proof that the initiator can receive
//! packets at its claimed IP before processing expensive DH operations.
//!
//! Flow:
//! 1. Initiator sends handshake with MAC2 = zeros
//! 2. Responder under load sends Cookie Reply
//! 3. Initiator decrypts cookie, resends with MAC2 = MAC(cookie, msg)
//! 4. Responder verifies MAC2, processes handshake

const COOKIE_SECRET_LIFETIME_NS: u64 = 120 * 1_000_000_000;
const COOKIE_LEN: usize = 16;
const LABEL_COOKIE: &[u8] = b"cookie--";
const LABEL_MAC1: &[u8] = b"mac1----";

extern "C" {
    fn wg_blake2s_hash(
        chunks: *const *const u8, chunk_lens: *const u32,
        num_chunks: u32, out: *mut u8,
    );
    fn wg_blake2s_256_mac(
        key: *const u8, key_len: u32, data: *const u8, data_len: u32, out: *mut u8,
    );
    fn wg_xchacha20poly1305_encrypt(
        key: *const u8, nonce: *const u8, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_xchacha20poly1305_decrypt(
        key: *const u8, nonce: *const u8, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_get_random_bytes(buf: *mut u8, len: u32);
    fn ktime_get_ns() -> u64;
}

fn hash(chunks: &[&[u8]]) -> [u8; 32] {
    let mut ptrs = [core::ptr::null(); 4];
    let mut lens = [0u32; 4];
    for (i, c) in chunks.iter().enumerate().take(4) {
        ptrs[i] = c.as_ptr();
        lens[i] = c.len() as u32;
    }
    let mut out = [0u8; 32];
    unsafe { wg_blake2s_hash(ptrs.as_ptr(), lens.as_ptr(), chunks.len() as u32, out.as_mut_ptr()) };
    out
}

fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { wg_blake2s_256_mac(key.as_ptr(), key.len() as u32, data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    unsafe { wg_get_random_bytes(buf.as_mut_ptr(), N as u32) };
    buf
}

/// Server-side: generates cookies and validates MAC2.
pub(crate) struct CookieChecker {
    our_public: [u8; 32],
    secret: [u8; 32],
    secret_generated: u64,
    pub(crate) under_load: bool,
}

/// Client-side: stores a received cookie for MAC2.
pub(crate) struct CookieState {
    cookie: Option<[u8; COOKIE_LEN]>,
    received: u64,
}

impl CookieChecker {
    pub(crate) fn new(our_public: [u8; 32]) -> Self {
        Self {
            our_public,
            secret: random_bytes(),
            secret_generated: unsafe { ktime_get_ns() },
            under_load: false,
        }
    }

    fn maybe_rotate_secret(&mut self) {
        let now = unsafe { ktime_get_ns() };
        if now.saturating_sub(self.secret_generated) >= COOKIE_SECRET_LIFETIME_NS {
            self.secret = random_bytes();
            self.secret_generated = now;
        }
    }

    fn make_cookie(&mut self, addr_bytes: &[u8]) -> [u8; COOKIE_LEN] {
        self.maybe_rotate_secret();
        let full = mac(&self.secret, addr_bytes);
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&full[..COOKIE_LEN]);
        cookie
    }

    /// Verify MAC1 on an incoming message.
    pub(crate) fn verify_mac1(&self, msg_bytes: &[u8], mac1: &[u8]) -> bool {
        if mac1.len() < 16 { return false; }
        let key = hash(&[LABEL_MAC1, &self.our_public]);
        let expected = mac(&key, msg_bytes);
        constant_time_eq(&mac1[..16], &expected[..16])
    }

    /// Verify MAC2 from pre-encoded address bytes.
    pub(crate) fn verify_mac2(&mut self, msg_with_mac1: &[u8], mac2: &[u8], addr_bytes: &[u8]) -> bool {
        if mac2.len() < 16 { return false; }
        let cookie = self.make_cookie(addr_bytes);
        let expected = mac(&cookie, msg_with_mac1);
        constant_time_eq(&mac2[..16], &expected[..16])
    }

    /// Create a Cookie Reply message (type 3, 64 bytes).
    pub(crate) fn create_reply(
        &mut self, receiver_index: u32, mac1: &[u8; 16], addr_bytes: &[u8],
    ) -> [u8; 64] {
        let cookie = self.make_cookie(addr_bytes);
        let key = hash(&[LABEL_COOKIE, &self.our_public]);
        let nonce: [u8; 24] = random_bytes();

        let mut encrypted_cookie = [0u8; 32]; // 16 cookie + 16 tag
        unsafe {
            wg_xchacha20poly1305_encrypt(
                key.as_ptr(), nonce.as_ptr(),
                cookie.as_ptr(), COOKIE_LEN as u32,
                mac1.as_ptr(), 16,
                encrypted_cookie.as_mut_ptr(),
            );
        }

        let mut reply = [0u8; 64];
        reply[0..4].copy_from_slice(&3u32.to_le_bytes()); // MSG_COOKIE_REPLY
        reply[4..8].copy_from_slice(&receiver_index.to_le_bytes());
        reply[8..32].copy_from_slice(&nonce);
        reply[32..64].copy_from_slice(&encrypted_cookie);
        reply
    }
}

impl CookieState {
    pub(crate) fn new() -> Self {
        Self { cookie: None, received: 0 }
    }

    /// Process a Cookie Reply and store the decrypted cookie.
    pub(crate) fn process_reply(
        &mut self, reply: &[u8; 64], their_public: &[u8; 32], our_mac1: &[u8; 16],
    ) -> bool {
        let nonce: [u8; 24] = reply[8..32].try_into().unwrap_or([0; 24]);
        let encrypted = &reply[32..64];

        let key = hash(&[LABEL_COOKIE, their_public]);
        let mut cookie = [0u8; COOKIE_LEN];

        let ret = unsafe {
            wg_xchacha20poly1305_decrypt(
                key.as_ptr(), nonce.as_ptr(),
                encrypted.as_ptr(), encrypted.len() as u32,
                our_mac1.as_ptr(), 16,
                cookie.as_mut_ptr(),
            )
        };

        if ret == 0 {
            self.cookie = Some(cookie);
            self.received = unsafe { ktime_get_ns() };
            true
        } else {
            false
        }
    }

    /// Compute MAC2 using our stored cookie. Returns zeros if no fresh cookie.
    pub(crate) fn compute_mac2(&self, msg_with_mac1: &[u8]) -> [u8; 16] {
        match &self.cookie {
            Some(cookie) if self.is_fresh() => {
                let full = mac(cookie, msg_with_mac1);
                let mut mac2 = [0u8; 16];
                mac2.copy_from_slice(&full[..16]);
                mac2
            }
            _ => [0u8; 16],
        }
    }

    fn is_fresh(&self) -> bool {
        if self.received == 0 { return false; }
        let now = unsafe { ktime_get_ns() };
        now.saturating_sub(self.received) < COOKIE_SECRET_LIFETIME_NS
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
