//! WireGuard Noise_IKpsk2 handshake.
//!
//! The handshake is a 1-RTT key exchange:
//!   Initiator -> Responder: ephemeral, encrypted static, encrypted timestamp
//!   Responder -> Initiator: ephemeral, encrypted empty
//!
//! After this exchange both sides derive symmetric transport keys.
//! The chaining key (ck) and handshake hash (h) are threaded through
//! every operation — this is the Noise pattern in action.

use alloc::vec::Vec;
use rustguard_crypto::{
    self as crypto, EphemeralSecret, PublicKey, SharedSecret, StaticSecret, Tai64n,
    CONSTRUCTION, IDENTIFIER, LABEL_MAC1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::messages::{Initiation, Response};
use crate::session::TransportSession;

/// Precomputed initial handshake state from the protocol constants.
/// These are the same for every handshake — compute once.
fn initial_chain_key() -> [u8; 32] {
    crypto::hash(&[CONSTRUCTION])
}

fn initial_hash(ck: &[u8; 32]) -> [u8; 32] {
    crypto::hash(&[ck, IDENTIFIER])
}

/// Mix a public key into the hash. Used to bind the responder's identity.
fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    crypto::hash(&[h, data])
}

/// Mix the result of a DH into the chaining key.
/// Returns (new_ck, key) where key is for AEAD encryption.
fn mix_key(ck: &[u8; 32], dh_result: &SharedSecret) -> ([u8; 32], [u8; 32]) {
    let (new_ck, key, _) = crypto::hkdf(ck, dh_result.as_bytes());
    (new_ck, key)
}

/// Encrypt-and-hash: AEAD encrypt, then mix ciphertext into hash.
fn encrypt_and_hash(key: &[u8; 32], h: &[u8; 32], plaintext: &[u8]) -> ([u8; 32], Vec<u8>) {
    let ciphertext = crypto::seal(key, 0, h, plaintext);
    let new_h = mix_hash(h, &ciphertext);
    (new_h, ciphertext)
}

/// Decrypt-and-hash: AEAD decrypt, then mix ciphertext into hash.
fn decrypt_and_hash(key: &[u8; 32], h: &[u8; 32], ciphertext: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let plaintext = crypto::open(key, 0, h, ciphertext)?;
    let new_h = mix_hash(h, ciphertext);
    Some((new_h, plaintext))
}

/// Compute MAC1 over a message using the responder's public key.
/// MAC1 = BLAKE2s-MAC(HASH(LABEL_MAC1 || responder_public), msg_bytes)
pub fn compute_mac1(responder_public: &PublicKey, msg_bytes: &[u8]) -> [u8; 16] {
    let key = crypto::hash(&[LABEL_MAC1, responder_public.as_ref()]);
    let full_mac = crypto::mac(&key, &[msg_bytes]);
    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&full_mac[..16]);
    mac1
}

// ── Initiator side ──────────────────────────────────────────────────

/// State held by the initiator between sending msg1 and receiving msg2.
/// Zeroized on drop to prevent key material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorHandshake {
    ck: [u8; 32],
    h: [u8; 32],
    ephemeral: EphemeralSecret,
    #[zeroize(skip)]
    sender_index: u32,
    #[zeroize(skip)]
    their_public: PublicKey,
    psk: [u8; 32],
}

/// Create a handshake initiation message (std convenience — uses OsRng and system clock).
#[cfg(feature = "std")]
pub fn create_initiation(
    our_static: &StaticSecret,
    their_public: &PublicKey,
    sender_index: u32,
) -> (Initiation, InitiatorHandshake) {
    create_initiation_psk(our_static, their_public, sender_index, &[0u8; 32])
}

/// Create a handshake initiation with PSK (std convenience).
#[cfg(feature = "std")]
pub fn create_initiation_psk(
    our_static: &StaticSecret,
    their_public: &PublicKey,
    sender_index: u32,
    psk: &[u8; 32],
) -> (Initiation, InitiatorHandshake) {
    let ephemeral = EphemeralSecret::random();
    let timestamp = Tai64n::now();
    create_initiation_with(our_static, their_public, sender_index, psk, ephemeral, timestamp)
}

/// Create a handshake initiation with explicit ephemeral key and timestamp.
/// This is the core function — usable from both std and no_std.
pub fn create_initiation_with(
    our_static: &StaticSecret,
    their_public: &PublicKey,
    sender_index: u32,
    psk: &[u8; 32],
    ephemeral: EphemeralSecret,
    timestamp: Tai64n,
) -> (Initiation, InitiatorHandshake) {
    let mut ck = initial_chain_key();
    let mut h = initial_hash(&ck);

    // Mix responder's public key into hash — both sides know this.
    h = mix_hash(&h, their_public.as_ref());

    let eph_public = ephemeral.public_key();

    // Mix ephemeral public into hash.
    h = mix_hash(&h, eph_public.as_ref());

    // DH(ephemeral, responder_static) -> mix into ck.
    let dh1 = ephemeral.diffie_hellman(their_public);
    let key;
    (ck, key) = mix_key(&ck, &dh1);

    // Encrypt our static public key.
    let our_public = our_static.public_key();
    let encrypted_static;
    (h, encrypted_static) = encrypt_and_hash(&key, &h, our_public.as_ref());

    // DH(our_static, responder_static) -> mix into ck.
    let dh2 = our_static.diffie_hellman(their_public);
    let key2;
    (ck, key2) = mix_key(&ck, &dh2);

    // Encrypt timestamp.
    let encrypted_timestamp;
    (h, encrypted_timestamp) = encrypt_and_hash(&key2, &h, timestamp.as_bytes());

    // Build message (mac1/mac2 computed over wire bytes).
    let mut msg = Initiation {
        sender_index,
        ephemeral: *eph_public.as_bytes(),
        encrypted_static: encrypted_static.try_into().expect("static is 48 bytes"),
        encrypted_timestamp: encrypted_timestamp.try_into().expect("timestamp is 28 bytes"),
        mac1: [0u8; 16],
        mac2: [0u8; 16], // No cookie mechanism yet.
    };

    // MAC1 is computed over everything before mac1 field.
    let wire = msg.to_bytes();
    msg.mac1 = compute_mac1(their_public, &wire[..116]);

    let state = InitiatorHandshake {
        ck,
        h,
        ephemeral,
        sender_index,
        their_public: their_public.clone(),
        psk: *psk,
    };

    (msg, state)
}

/// Process a handshake response and derive transport keys.
pub fn process_response(
    state: InitiatorHandshake,
    our_static: &StaticSecret,
    msg: &Response,
) -> Option<TransportSession> {
    // Access fields by reference — struct will zeroize on drop.
    let mut ck = state.ck;
    let mut h = state.h;
    let sender_index = state.sender_index;
    let psk = state.psk;

    // Verify receiver_index matches our sender_index.
    if msg.receiver_index != sender_index {
        return None;
    }

    // ── Verify MAC1 FIRST — cheap check before any DH. ──
    // MAC1 is keyed with HASH(LABEL_MAC1 || initiator_public), computed over
    // the response bytes before the mac1 field (first 60 bytes).
    let our_public = our_static.public_key();
    let wire = msg.to_bytes();
    let expected_mac1 = compute_mac1(&our_public, &wire[..60]);
    if !constant_time_eq(&msg.mac1, &expected_mac1) {
        return None;
    }

    let resp_eph = PublicKey::from_bytes(msg.ephemeral);

    // Mix responder ephemeral into hash.
    h = mix_hash(&h, resp_eph.as_ref());

    // DH(our_ephemeral, responder_ephemeral)
    let dh1 = state.ephemeral.diffie_hellman(&resp_eph);
    (ck, _) = mix_key(&ck, &dh1);

    // DH(our_static, responder_ephemeral)
    let dh2 = our_static.diffie_hellman(&resp_eph);
    (ck, _) = mix_key(&ck, &dh2);

    // PSK phase (Noise_IKpsk2): mix PSK into chain.
    let (new_ck, t, key) = crypto::hkdf(&ck, &psk);
    ck = new_ck;
    h = mix_hash(&h, &t);

    // Decrypt empty payload.
    let result = decrypt_and_hash(&key, &h, &msg.encrypted_empty);
    let (h, _empty) = result?;
    let _ = h;

    // Derive transport keys: initiator sends with first, receives with second.
    let (send_key, recv_key, _) = crypto::hkdf(&ck, &[]);

    Some(TransportSession::new(
        sender_index,
        msg.sender_index,
        send_key,
        recv_key,
    ))
}

// ── Responder side ──────────────────────────────────────────────────

/// Process a handshake initiation on the responder side (std convenience).
#[cfg(feature = "std")]
pub fn process_initiation(
    our_static: &StaticSecret,
    msg: &Initiation,
    responder_index: u32,
) -> Option<(PublicKey, Tai64n, Response, TransportSession)> {
    process_initiation_psk(our_static, msg, responder_index, &[0u8; 32], None)
}

/// Process a handshake initiation with PSK (std convenience).
#[cfg(feature = "std")]
pub fn process_initiation_psk(
    our_static: &StaticSecret,
    msg: &Initiation,
    responder_index: u32,
    psk: &[u8; 32],
    last_timestamp: Option<&Tai64n>,
) -> Option<(PublicKey, Tai64n, Response, TransportSession)> {
    let resp_eph = EphemeralSecret::random();
    process_initiation_with(our_static, msg, responder_index, psk, last_timestamp, resp_eph)
}

/// Process a handshake initiation with explicit ephemeral (no_std compatible).
pub fn process_initiation_with(
    our_static: &StaticSecret,
    msg: &Initiation,
    responder_index: u32,
    psk: &[u8; 32],
    last_timestamp: Option<&Tai64n>,
    resp_eph: EphemeralSecret,
) -> Option<(PublicKey, Tai64n, Response, TransportSession)> {
    let our_public = our_static.public_key();

    // ── Verify MAC1 FIRST — cheap check before any DH. ──
    let wire = msg.to_bytes();
    let expected_mac1 = compute_mac1(&our_public, &wire[..116]);
    if !constant_time_eq(&msg.mac1, &expected_mac1) {
        return None;
    }
    // TODO: MAC2 / cookie validation under load.

    let mut ck = initial_chain_key();
    let mut h = initial_hash(&ck);

    // Mix our public key into hash (responder's identity).
    h = mix_hash(&h, our_public.as_ref());

    let init_eph = PublicKey::from_bytes(msg.ephemeral);

    // Mix initiator ephemeral into hash.
    h = mix_hash(&h, init_eph.as_ref());

    // DH(our_static, initiator_ephemeral)
    let dh1 = our_static.diffie_hellman(&init_eph);
    let key;
    (ck, key) = mix_key(&ck, &dh1);

    // Decrypt initiator's static public key.
    let (new_h, static_bytes) = decrypt_and_hash(&key, &h, &msg.encrypted_static)?;
    h = new_h;

    let initiator_public = PublicKey::from_bytes(
        static_bytes
            .as_slice()
            .try_into()
            .ok()?,
    );

    // DH(our_static, initiator_static)
    let dh2 = our_static.diffie_hellman(&initiator_public);
    let key2;
    (ck, key2) = mix_key(&ck, &dh2);

    // Decrypt timestamp.
    let (new_h, timestamp_bytes) = decrypt_and_hash(&key2, &h, &msg.encrypted_timestamp)?;
    h = new_h;

    // Validate timestamp is newer than last seen — prevents replay.
    let timestamp = Tai64n::from_bytes(
        timestamp_bytes.as_slice().try_into().ok()?,
    );
    if let Some(last) = last_timestamp {
        if !timestamp.is_after(last) {
            return None; // Replayed or stale initiation.
        }
    }

    // ── Build response ──

    let resp_eph_public = resp_eph.public_key();

    // Mix responder ephemeral into hash.
    h = mix_hash(&h, resp_eph_public.as_ref());

    // DH(resp_ephemeral, initiator_ephemeral)
    let dh3 = resp_eph.diffie_hellman(&init_eph);
    (ck, _) = mix_key(&ck, &dh3);

    // DH(resp_ephemeral, initiator_static)
    let dh4 = resp_eph.diffie_hellman(&initiator_public);
    (ck, _) = mix_key(&ck, &dh4);

    // PSK phase.
    let (new_ck, t, key3) = crypto::hkdf(&ck, psk);
    ck = new_ck;
    h = mix_hash(&h, &t);

    // Encrypt empty.
    let encrypted_empty;
    (h, encrypted_empty) = encrypt_and_hash(&key3, &h, &[]);
    let _ = h; // final hash

    // Derive transport keys: responder sends with second, receives with first.
    let (recv_key, send_key, _) = crypto::hkdf(&ck, &[]);

    let mut resp = Response {
        sender_index: responder_index,
        receiver_index: msg.sender_index,
        ephemeral: *resp_eph_public.as_bytes(),
        encrypted_empty: encrypted_empty.try_into().expect("empty encrypted is 16 bytes"),
        mac1: [0u8; 16],
        mac2: [0u8; 16],
    };

    // MAC1 on response.
    let resp_wire = resp.to_bytes();
    resp.mac1 = compute_mac1(&initiator_public, &resp_wire[..60]);

    let session = TransportSession::new(responder_index, msg.sender_index, send_key, recv_key);

    Some((initiator_public, timestamp, resp, session))
}

/// Constant-time comparison for MACs using the `subtle` crate.
fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_and_transport() {
        // Setup: both sides have static keys, initiator knows responder's public key.
        let initiator_static = StaticSecret::random();
        let responder_static = StaticSecret::random();
        let responder_public = responder_static.public_key();

        // Step 1: Initiator creates handshake initiation.
        let (init_msg, init_state) =
            create_initiation(&initiator_static, &responder_public, 1);

        // Step 2: Responder processes initiation, creates response.
        let (peer_pubkey, _ts, resp_msg, mut resp_session) =
            process_initiation(&responder_static, &init_msg, 2)
                .expect("responder should accept initiation");

        // Responder correctly identifies the initiator.
        assert_eq!(peer_pubkey, initiator_static.public_key());

        // Step 3: Initiator processes response, gets transport session.
        let mut init_session =
            process_response(init_state, &initiator_static, &resp_msg)
                .expect("initiator should accept response");

        // Step 4: Both sides can now exchange encrypted data.
        let plaintext = b"hello from the trenches";
        let (counter, ciphertext) = init_session.encrypt(plaintext).unwrap();
        let decrypted = resp_session
            .decrypt(counter, &ciphertext)
            .expect("responder should decrypt");
        assert_eq!(&decrypted, plaintext);

        // And the other direction.
        let reply = b"copy that, over";
        let (counter, ciphertext) = resp_session.encrypt(reply).unwrap();
        let decrypted = init_session
            .decrypt(counter, &ciphertext)
            .expect("initiator should decrypt");
        assert_eq!(&decrypted, reply);
    }

    #[test]
    fn wrong_responder_key_rejects() {
        let initiator_static = StaticSecret::random();
        let responder_static = StaticSecret::random();
        let wrong_static = StaticSecret::random();
        let responder_public = responder_static.public_key();

        let (init_msg, _) = create_initiation(&initiator_static, &responder_public, 1);

        // A different responder (wrong key) tries to process the initiation.
        let result = process_initiation(&wrong_static, &init_msg, 2);
        assert!(result.is_none(), "wrong responder key should fail");
    }

    #[test]
    fn tampered_initiation_rejected() {
        let initiator_static = StaticSecret::random();
        let responder_static = StaticSecret::random();
        let responder_public = responder_static.public_key();

        let (mut init_msg, _) = create_initiation(&initiator_static, &responder_public, 1);

        // Tamper with the encrypted static field.
        init_msg.encrypted_static[0] ^= 0xff;

        let result = process_initiation(&responder_static, &init_msg, 2);
        assert!(result.is_none(), "tampered initiation should fail");
    }

    #[test]
    fn tampered_response_rejected() {
        let initiator_static = StaticSecret::random();
        let responder_static = StaticSecret::random();
        let responder_public = responder_static.public_key();

        let (init_msg, init_state) =
            create_initiation(&initiator_static, &responder_public, 1);

        let (_, _ts, mut resp_msg, _) =
            process_initiation(&responder_static, &init_msg, 2).unwrap();

        // Tamper with the encrypted empty field.
        resp_msg.encrypted_empty[0] ^= 0xff;

        let result = process_response(init_state, &initiator_static, &resp_msg);
        assert!(result.is_none(), "tampered response should fail");
    }

    #[test]
    fn mismatched_receiver_index_rejected() {
        let initiator_static = StaticSecret::random();
        let responder_static = StaticSecret::random();
        let responder_public = responder_static.public_key();

        let (init_msg, init_state) =
            create_initiation(&initiator_static, &responder_public, 1);

        let (_, _ts, mut resp_msg, _) =
            process_initiation(&responder_static, &init_msg, 2).unwrap();

        // Change receiver_index to wrong value.
        resp_msg.receiver_index = 999;

        let result = process_response(init_state, &initiator_static, &resp_msg);
        assert!(result.is_none(), "wrong receiver index should fail");
    }
}
