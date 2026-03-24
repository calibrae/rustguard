use alloc::vec::Vec;
use rustguard_crypto::{self as crypto};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::replay::ReplayWindow;

/// A transport session derived from a completed handshake.
///
/// Each side gets a sending key and a receiving key.
/// The initiator sends with key_send and receives with key_recv.
/// The responder has these reversed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransportSession {
    /// Our sender index (the other side uses this as receiver_index).
    #[zeroize(skip)]
    pub our_index: u32,
    /// Their sender index (we use this as receiver_index in incoming packets).
    #[zeroize(skip)]
    pub their_index: u32,
    /// Key for encrypting outgoing packets.
    key_send: [u8; 32],
    /// Key for decrypting incoming packets.
    key_recv: [u8; 32],
    /// Outgoing nonce counter.
    #[zeroize(skip)]
    send_counter: u64,
    /// Anti-replay window for incoming packets.
    #[zeroize(skip)]
    recv_window: ReplayWindow,
}

impl TransportSession {
    pub fn new(
        our_index: u32,
        their_index: u32,
        key_send: [u8; 32],
        key_recv: [u8; 32],
    ) -> Self {
        Self {
            our_index,
            their_index,
            key_send,
            key_recv,
            send_counter: 0,
            recv_window: ReplayWindow::new(),
        }
    }

    /// Encrypt a plaintext packet for transport.
    /// Returns None if the nonce counter has been exhausted (rekey required).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Option<(u64, Vec<u8>)> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.checked_add(1)?;
        let ciphertext = crypto::seal(&self.key_send, counter, &[], plaintext);
        Some((counter, ciphertext))
    }

    /// Decrypt an incoming transport packet.
    /// Checks the anti-replay window before decrypting.
    /// Only marks the counter as seen after AEAD succeeds.
    /// Returns None if replay detected or decryption fails.
    pub fn decrypt(&mut self, counter: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Check replay window first — cheap before expensive AEAD.
        if !self.recv_window.check(counter) {
            return None;
        }
        // Attempt decryption. Only update replay window on success
        // to prevent an attacker from poisoning the window with garbage.
        let plaintext = crypto::open(&self.key_recv, counter, &[], ciphertext)?;
        self.recv_window.update(counter);
        Some(plaintext)
    }

    /// Zero-alloc encrypt: writes ciphertext into `out` buffer.
    /// Returns (counter, ciphertext_len) or None if nonce exhausted.
    /// `out` must be at least `plaintext.len() + 16` bytes.
    pub fn encrypt_to(&mut self, plaintext: &[u8], out: &mut [u8]) -> Option<(u64, usize)> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.checked_add(1)?;
        let ct_len = crypto::seal_to(&self.key_send, counter, plaintext, out);
        Some((counter, ct_len))
    }

    /// Zero-alloc decrypt: decrypts in place within `buf`.
    /// `buf[..ct_len]` contains ciphertext+tag on input, plaintext on output.
    /// Returns plaintext length or None.
    pub fn decrypt_in_place(&mut self, counter: u64, buf: &mut [u8], ct_len: usize) -> Option<usize> {
        if !self.recv_window.check(counter) {
            return None;
        }
        let pt_len = crypto::open_to(&self.key_recv, counter, buf, ct_len)?;
        self.recv_window.update(counter);
        Some(pt_len)
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_pair() -> (TransportSession, TransportSession) {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let initiator = TransportSession::new(1, 2, key_a, key_b);
        let responder = TransportSession::new(2, 1, key_b, key_a);
        (initiator, responder)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut initiator, mut responder) = make_session_pair();
        let plaintext = b"ping from the trenches";

        let (counter, ciphertext) = initiator.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + crypto::AEAD_TAG_LEN);

        let decrypted = responder.decrypt(counter, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn counter_increments() {
        let (mut initiator, _) = make_session_pair();
        assert_eq!(initiator.send_counter(), 0);
        initiator.encrypt(b"one").unwrap();
        assert_eq!(initiator.send_counter(), 1);
        initiator.encrypt(b"two").unwrap();
        assert_eq!(initiator.send_counter(), 2);
    }

    #[test]
    fn wrong_counter_fails() {
        let (mut initiator, mut responder) = make_session_pair();
        let (counter, ciphertext) = initiator.encrypt(b"data").unwrap();
        assert!(responder.decrypt(counter + 1, &ciphertext).is_none());
    }

    #[test]
    fn replay_rejected() {
        let (mut initiator, mut responder) = make_session_pair();
        let (counter, ciphertext) = initiator.encrypt(b"data").unwrap();
        assert!(responder.decrypt(counter, &ciphertext).is_some());
        assert!(
            responder.decrypt(counter, &ciphertext).is_none(),
            "replayed packet must be rejected"
        );
    }

    #[test]
    fn out_of_order_accepted() {
        let (mut initiator, mut responder) = make_session_pair();

        let (c0, ct0) = initiator.encrypt(b"zero").unwrap();
        let (c1, ct1) = initiator.encrypt(b"one").unwrap();
        let (c2, ct2) = initiator.encrypt(b"two").unwrap();

        // Deliver out of order: 2, 0, 1.
        assert_eq!(responder.decrypt(c2, &ct2).unwrap(), b"two");
        assert_eq!(responder.decrypt(c0, &ct0).unwrap(), b"zero");
        assert_eq!(responder.decrypt(c1, &ct1).unwrap(), b"one");
    }

    #[test]
    fn bidirectional() {
        let (mut initiator, mut responder) = make_session_pair();

        let (c1, ct1) = initiator.encrypt(b"hello").unwrap();
        let (c2, ct2) = responder.encrypt(b"world").unwrap();

        assert_eq!(responder.decrypt(c1, &ct1).unwrap(), b"hello");
        assert_eq!(initiator.decrypt(c2, &ct2).unwrap(), b"world");
    }
}
