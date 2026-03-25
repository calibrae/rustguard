// SPDX-License-Identifier: GPL-2.0

//! Noise_IKpsk2 handshake for WireGuard.
//!
//! Implements the full 1-RTT key exchange:
//!   Initiator → Responder: ephemeral pub, encrypted static pub, encrypted timestamp
//!   Responder → Initiator: ephemeral pub, encrypted empty
//!
//! After this exchange both sides derive symmetric transport keys.
//! All crypto calls go through the C shim (wg_crypto.c).

use crate::AEAD_TAG_SIZE;
use core::sync::atomic::AtomicU64;

// ── FFI ───────────────────────────────────────────────────────────────

extern "C" {
    fn wg_chacha20poly1305_encrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_chacha20poly1305_decrypt(
        key: *const u8, nonce: u64, src: *const u8, src_len: u32,
        ad: *const u8, ad_len: u32, dst: *mut u8,
    ) -> i32;
    fn wg_blake2s_hash(
        chunks: *const *const u8, chunk_lens: *const u32,
        num_chunks: u32, out: *mut u8,
    );
    fn wg_blake2s_256_mac(
        key: *const u8, key_len: u32, data: *const u8, data_len: u32, out: *mut u8,
    );
    fn wg_hkdf(
        key: *const u8, input: *const u8, input_len: u32,
        out1: *mut u8, out2: *mut u8, out3: *mut u8,
    );
    fn wg_curve25519(out: *mut u8, scalar: *const u8, point: *const u8) -> i32;
    fn wg_curve25519_generate_secret(secret: *mut u8);
    fn wg_curve25519_generate_public(pub_key: *mut u8, secret: *const u8);
    fn wg_get_random_bytes(buf: *mut u8, len: u32);
    fn wg_memzero(ptr: *mut u8, len: usize);
    fn wg_crypto_memneq(a: *const u8, b: *const u8, len: usize) -> i32;
}

/// Zeroize a mutable byte slice using memzero_explicit (cannot be optimized away).
pub(crate) fn zeroize(buf: &mut [u8]) {
    if !buf.is_empty() {
        unsafe { wg_memzero(buf.as_mut_ptr(), buf.len()) };
    }
}

/// Constant-time equality comparison using kernel crypto_memneq.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    unsafe { wg_crypto_memneq(a.as_ptr(), b.as_ptr(), a.len()) == 0 }
}

// ── WireGuard protocol constants ──────────────────────────────────────

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

/// TAI64N epoch offset (2^62 + 10 leap seconds).
const TAI64_EPOCH_OFFSET: u64 = 0x4000_0000_0000_000a;

// ── Crypto helpers (calling C shim) ───────────────────────────────────

/// BLAKE2s-256 hash of concatenated chunks (max 8).
fn hash(chunks: &[&[u8]]) -> [u8; 32] {
    // Cap at 8 — the C shim receives exactly this many pointers.
    let num = if chunks.len() > 8 { 8 } else { chunks.len() };
    let ptrs: [*const u8; 8] = {
        let mut p = [core::ptr::null(); 8];
        for (i, c) in chunks.iter().enumerate().take(num) {
            p[i] = c.as_ptr();
        }
        p
    };
    let lens: [u32; 8] = {
        let mut l = [0u32; 8];
        for (i, c) in chunks.iter().enumerate().take(num) {
            l[i] = c.len() as u32;
        }
        l
    };
    let mut out = [0u8; 32];
    unsafe {
        wg_blake2s_hash(ptrs.as_ptr(), lens.as_ptr(), num as u32, out.as_mut_ptr());
    }
    out
}

/// Keyed BLAKE2s MAC (for MAC1/MAC2).
fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        wg_blake2s_256_mac(
            key.as_ptr(), key.len() as u32,
            data.as_ptr(), data.len() as u32,
            out.as_mut_ptr(),
        );
    }
    out
}

/// HKDF extract + expand.
fn hkdf(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut o1 = [0u8; 32];
    let mut o2 = [0u8; 32];
    let mut o3 = [0u8; 32];
    unsafe {
        wg_hkdf(
            key.as_ptr(), input.as_ptr(), input.len() as u32,
            o1.as_mut_ptr(), o2.as_mut_ptr(), o3.as_mut_ptr(),
        );
    }
    (o1, o2, o3)
}

/// AEAD encrypt (ChaCha20-Poly1305). Returns ciphertext + 16-byte tag, or None on failure.
fn seal(key: &[u8; 32], counter: u64, ad: &[u8], plaintext: &[u8], dst: &mut [u8]) -> Option<usize> {
    let ret = unsafe {
        wg_chacha20poly1305_encrypt(
            key.as_ptr(), counter,
            plaintext.as_ptr(), plaintext.len() as u32,
            ad.as_ptr(), ad.len() as u32,
            dst.as_mut_ptr(),
        )
    };
    if ret == 0 {
        Some(plaintext.len() + AEAD_TAG_SIZE)
    } else {
        None
    }
}

/// AEAD decrypt. Returns plaintext length or None on auth failure.
fn open(key: &[u8; 32], counter: u64, ad: &[u8], ciphertext: &[u8], dst: &mut [u8]) -> Option<usize> {
    let ret = unsafe {
        wg_chacha20poly1305_decrypt(
            key.as_ptr(), counter,
            ciphertext.as_ptr(), ciphertext.len() as u32,
            ad.as_ptr(), ad.len() as u32,
            dst.as_mut_ptr(),
        )
    };
    if ret == 0 {
        Some(ciphertext.len() - AEAD_TAG_SIZE)
    } else {
        None
    }
}

/// Curve25519 DH.
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let ret = unsafe { wg_curve25519(out.as_mut_ptr(), secret.as_ptr(), public.as_ptr()) };
    if ret == 0 { Some(out) } else { None }
}

/// Generate ephemeral keypair.
fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    let mut public = [0u8; 32];
    unsafe {
        wg_curve25519_generate_secret(secret.as_mut_ptr());
        wg_curve25519_generate_public(public.as_mut_ptr(), secret.as_ptr());
    }
    (secret, public)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    unsafe { wg_get_random_bytes(buf.as_mut_ptr(), N as u32) };
    buf
}

// ── Noise helpers ─────────────────────────────────────────────────────

fn initial_chain_key() -> [u8; 32] {
    hash(&[CONSTRUCTION])
}

fn initial_hash(ck: &[u8; 32]) -> [u8; 32] {
    hash(&[ck, IDENTIFIER])
}

fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hash(&[h, data])
}

fn mix_key(ck: &[u8; 32], dh_result: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (new_ck, key, _) = hkdf(ck, dh_result);
    (new_ck, key)
}

/// Encrypt-and-hash: AEAD encrypt, mix ciphertext into hash.
fn encrypt_and_hash(key: &[u8; 32], h: &[u8; 32], plaintext: &[u8], ct_buf: &mut [u8]) -> Option<([u8; 32], usize)> {
    let ct_len = seal(key, 0, h, plaintext, ct_buf)?;
    let new_h = mix_hash(h, &ct_buf[..ct_len]);
    Some((new_h, ct_len))
}

/// Decrypt-and-hash: AEAD decrypt, mix ciphertext into hash.
fn decrypt_and_hash(key: &[u8; 32], h: &[u8; 32], ciphertext: &[u8], pt_buf: &mut [u8]) -> Option<([u8; 32], usize)> {
    let pt_len = open(key, 0, h, ciphertext, pt_buf)?;
    let new_h = mix_hash(h, ciphertext);
    Some((new_h, pt_len))
}

/// Compute MAC1 over a message.
fn compute_mac1(responder_public: &[u8; 32], msg_bytes: &[u8]) -> [u8; 16] {
    let key = hash(&[LABEL_MAC1, responder_public]);
    let full = mac(&key, msg_bytes);
    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&full[..16]);
    mac1
}

// ── TAI64N timestamp ──────────────────────────────────────────────────

/// Generate a TAI64N timestamp from kernel wall clock.
fn tai64n_now() -> [u8; 12] {
    extern "C" {
        fn wg_ktime_get_real(secs: *mut i64, nsecs: *mut i64);
    }
    let mut secs: i64 = 0;
    let mut nsecs: i64 = 0;
    unsafe { wg_ktime_get_real(&mut secs, &mut nsecs) };

    let tai_secs = (secs as u64) + TAI64_EPOCH_OFFSET;
    let nanos = nsecs as u32;
    let mut buf = [0u8; 12];
    buf[..8].copy_from_slice(&tai_secs.to_be_bytes());
    buf[8..].copy_from_slice(&nanos.to_be_bytes());
    buf
}

// ── Wire format constants ─────────────────────────────────────────────

/// Message type 1: Handshake Initiation (148 bytes).
pub(crate) const MSG_INITIATION: u32 = 1;
/// Message type 2: Handshake Response (92 bytes).
pub(crate) const MSG_RESPONSE: u32 = 2;
/// Message type 4: Transport Data.
pub(crate) const MSG_TRANSPORT: u32 = 4;

pub(crate) const INITIATION_SIZE: usize = 148;
pub(crate) const RESPONSE_SIZE: usize = 92;

// ── Transport session ─────────────────────────────────────────────────

/// Derived transport keys from a completed handshake.
pub(crate) struct TransportKeys {
    /// Key for encrypting outgoing packets.
    pub(crate) key_send: [u8; 32],
    /// Key for decrypting incoming packets.
    pub(crate) key_recv: [u8; 32],
    /// Our sender index.
    pub(crate) our_index: u32,
    /// Their sender index.
    pub(crate) their_index: u32,
    /// Outgoing nonce counter.
    pub(crate) send_counter: AtomicU64,
}

// ── Initiator handshake ───────────────────────────────────────────────

/// State held between sending initiation and receiving response.
pub(crate) struct InitiatorState {
    ck: [u8; 32],
    h: [u8; 32],
    eph_secret: [u8; 32],
    pub(crate) sender_index: u32,
    their_public: [u8; 32],
    psk: [u8; 32],
}

/// Create a handshake initiation message (type 1).
///
/// Returns the 148-byte wire message and the state needed to process the response,
/// or None if a DH operation produces a zero result (low-order point attack).
pub(crate) fn create_initiation(
    our_static_secret: &[u8; 32],
    our_static_public: &[u8; 32],
    their_public: &[u8; 32],
    sender_index: u32,
    psk: &[u8; 32],
) -> Option<([u8; INITIATION_SIZE], InitiatorState)> {
    let mut ck = initial_chain_key();
    let mut h = initial_hash(&ck);

    // Mix responder's public key.
    h = mix_hash(&h, their_public);

    // Generate ephemeral keypair.
    let (mut eph_secret, eph_public) = generate_keypair();

    h = mix_hash(&h, &eph_public);

    // DH(ephemeral, responder_static) — C2: fail on zero result.
    let mut dh1 = dh(&eph_secret, their_public)?;
    let mut key;
    (ck, key) = mix_key(&ck, &dh1);
    zeroize(&mut dh1);

    // Encrypt our static public key.
    let mut encrypted_static = [0u8; 48]; // 32 + 16 tag
    (h, _) = encrypt_and_hash(&key, &h, our_static_public, &mut encrypted_static)?;
    zeroize(&mut key);

    // DH(our_static, responder_static) — C2: fail on zero result.
    let mut dh2 = dh(our_static_secret, their_public)?;
    let mut key2;
    (ck, key2) = mix_key(&ck, &dh2);
    zeroize(&mut dh2);

    // Encrypt timestamp.
    let timestamp = tai64n_now();
    let mut encrypted_timestamp = [0u8; 28]; // 12 + 16 tag
    (h, _) = encrypt_and_hash(&key2, &h, &timestamp, &mut encrypted_timestamp)?;
    zeroize(&mut key2);

    // Build wire message.
    let mut msg = [0u8; INITIATION_SIZE];
    msg[0..4].copy_from_slice(&MSG_INITIATION.to_le_bytes());
    msg[4..8].copy_from_slice(&sender_index.to_le_bytes());
    msg[8..40].copy_from_slice(&eph_public);
    msg[40..88].copy_from_slice(&encrypted_static);
    msg[88..116].copy_from_slice(&encrypted_timestamp);
    // mac1 over everything before mac1 field (bytes 0..116).
    let mac1 = compute_mac1(their_public, &msg[..116]);
    msg[116..132].copy_from_slice(&mac1);
    // mac2 = zeros (no cookie).
    // msg[132..148] already zero.

    let state = InitiatorState {
        ck, h, eph_secret, sender_index,
        their_public: *their_public,
        psk: *psk,
    };
    // C3: zero the local eph_secret copy (state has its own copy).
    zeroize(&mut eph_secret);

    Some((msg, state))
}

/// Process a handshake response (type 2) and derive transport keys.
pub(crate) fn process_response(
    mut state: InitiatorState,
    our_static_secret: &[u8; 32],
    resp: &[u8; RESPONSE_SIZE],
) -> Option<TransportKeys> {
    // H6: Verify MAC1 before any DH operations.
    // The responder computed MAC1 as compute_mac1(&initiator_public, &resp[..60]).
    // We are the initiator — derive our public key from our secret to verify.
    let mut our_static_public = [0u8; 32];
    unsafe { wg_curve25519_generate_public(our_static_public.as_mut_ptr(), our_static_secret.as_ptr()) };
    let expected_mac1 = compute_mac1(&our_static_public, &resp[..60]);
    if !constant_time_eq(&resp[60..76], &expected_mac1) {
        zeroize(&mut state.ck);
        zeroize(&mut state.h);
        zeroize(&mut state.eph_secret);
        return None;
    }

    let mut ck = state.ck;
    let mut h = state.h;

    // Parse response.
    let resp_sender = u32::from_le_bytes(resp[4..8].try_into().ok()?);
    let resp_receiver = u32::from_le_bytes(resp[8..12].try_into().ok()?);
    if resp_receiver != state.sender_index {
        zeroize(&mut ck);
        zeroize(&mut h);
        zeroize(&mut state.eph_secret);
        return None;
    }

    let resp_eph: [u8; 32] = resp[12..44].try_into().ok()?;
    let encrypted_empty: &[u8] = &resp[44..60]; // 16 bytes (0 + 16 tag)

    // Mix responder ephemeral.
    h = mix_hash(&h, &resp_eph);

    // DH(our_ephemeral, responder_ephemeral).
    let mut dh1 = dh(&state.eph_secret, &resp_eph)?;
    (ck, _) = mix_key(&ck, &dh1);
    zeroize(&mut dh1);

    // DH(our_static, responder_ephemeral).
    let mut dh2 = dh(our_static_secret, &resp_eph)?;
    (ck, _) = mix_key(&ck, &dh2);
    zeroize(&mut dh2);

    // PSK phase.
    let (new_ck, mut t, key) = hkdf(&ck, &state.psk);
    ck = new_ck;
    h = mix_hash(&h, &t);
    zeroize(&mut t);

    // Decrypt empty payload.
    let mut empty = [0u8; 0];
    let (_, _) = decrypt_and_hash(&key, &h, encrypted_empty, &mut empty)?;

    // Derive transport keys: initiator sends with first, receives with second.
    let (send_key, recv_key, _) = hkdf(&ck, &[]);

    // C3: zeroize intermediate key material.
    zeroize(&mut ck);
    zeroize(&mut h);
    zeroize(&mut state.eph_secret);
    zeroize(&mut state.ck);
    zeroize(&mut state.h);
    zeroize(&mut state.psk);

    Some(TransportKeys {
        key_send: send_key,
        key_recv: recv_key,
        our_index: state.sender_index,
        their_index: resp_sender,
        send_counter: AtomicU64::new(0),
    })
}

// ── Responder handshake ───────────────────────────────────────────────

/// Process a handshake initiation (type 1) and generate a response (type 2).
///
/// Returns: (initiator_public_key, timestamp, response_message, transport_keys)
/// The caller MUST check the timestamp against the peer's last_timestamp for replay
/// protection (H3).
pub(crate) fn process_initiation(
    our_static_secret: &[u8; 32],
    our_static_public: &[u8; 32],
    msg: &[u8; INITIATION_SIZE],
    responder_index: u32,
    psk: &[u8; 32],
) -> Option<([u8; 32], [u8; 12], [u8; RESPONSE_SIZE], TransportKeys)> {
    // Verify MAC1 first — cheap check before any DH.
    let expected_mac1 = compute_mac1(our_static_public, &msg[..116]);
    if !constant_time_eq(&msg[116..132], &expected_mac1) {
        return None;
    }

    let init_sender = u32::from_le_bytes(msg[4..8].try_into().ok()?);
    let init_eph: [u8; 32] = msg[8..40].try_into().ok()?;

    let mut ck = initial_chain_key();
    let mut h = initial_hash(&ck);

    // Mix our public key.
    h = mix_hash(&h, our_static_public);

    // Mix initiator ephemeral.
    h = mix_hash(&h, &init_eph);

    // DH(our_static, initiator_ephemeral).
    let mut dh1 = dh(our_static_secret, &init_eph)?;
    let mut key;
    (ck, key) = mix_key(&ck, &dh1);
    zeroize(&mut dh1);

    // Decrypt initiator's static public key.
    let mut initiator_public = [0u8; 32];
    let (new_h, _) = decrypt_and_hash(&key, &h, &msg[40..88], &mut initiator_public)?;
    h = new_h;
    zeroize(&mut key);

    // DH(our_static, initiator_static).
    let mut dh2 = dh(our_static_secret, &initiator_public)?;
    let mut key2;
    (ck, key2) = mix_key(&ck, &dh2);
    zeroize(&mut dh2);

    // Decrypt timestamp — caller checks for replay (H3).
    let mut timestamp = [0u8; 12];
    let (new_h, _) = decrypt_and_hash(&key2, &h, &msg[88..116], &mut timestamp)?;
    h = new_h;
    zeroize(&mut key2);

    // ── Build response ──

    let (mut resp_eph_secret, resp_eph_public) = generate_keypair();
    h = mix_hash(&h, &resp_eph_public);

    // DH(resp_ephemeral, initiator_ephemeral).
    let mut dh3 = dh(&resp_eph_secret, &init_eph)?;
    (ck, _) = mix_key(&ck, &dh3);
    zeroize(&mut dh3);

    // DH(resp_ephemeral, initiator_static).
    let mut dh4 = dh(&resp_eph_secret, &initiator_public)?;
    (ck, _) = mix_key(&ck, &dh4);
    zeroize(&mut dh4);
    zeroize(&mut resp_eph_secret);

    // PSK phase.
    let (new_ck, mut t, mut key3) = hkdf(&ck, psk);
    ck = new_ck;
    h = mix_hash(&h, &t);
    zeroize(&mut t);

    // Encrypt empty.
    let mut encrypted_empty = [0u8; 16]; // 0 + 16 tag
    (h, _) = encrypt_and_hash(&key3, &h, &[], &mut encrypted_empty)?;
    zeroize(&mut key3);
    let _ = h;

    // Derive transport keys: responder sends with second, receives with first.
    let (recv_key, send_key, _) = hkdf(&ck, &[]);

    // C3: zeroize intermediate key material.
    zeroize(&mut ck);
    zeroize(&mut h);

    // Build response wire message.
    let mut resp = [0u8; RESPONSE_SIZE];
    resp[0..4].copy_from_slice(&MSG_RESPONSE.to_le_bytes());
    resp[4..8].copy_from_slice(&responder_index.to_le_bytes());
    resp[8..12].copy_from_slice(&init_sender.to_le_bytes());
    resp[12..44].copy_from_slice(&resp_eph_public);
    resp[44..60].copy_from_slice(&encrypted_empty);
    // MAC1 on response.
    let mac1 = compute_mac1(&initiator_public, &resp[..60]);
    resp[60..76].copy_from_slice(&mac1);
    // mac2 = zeros.

    let keys = TransportKeys {
        key_send: send_key,
        key_recv: recv_key,
        our_index: responder_index,
        their_index: init_sender,
        send_counter: AtomicU64::new(0),
    };

    Some((initiator_public, timestamp, resp, keys))
}

// ── Utility ───────────────────────────────────────────────────────────
// constant_time_eq and zeroize are defined at the top of this file,
// using kernel crypto_memneq and memzero_explicit respectively.
