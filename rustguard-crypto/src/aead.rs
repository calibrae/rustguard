use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
};

pub const AEAD_TAG_LEN: usize = 16;

/// Maximum WireGuard transport payload (MTU 1420 + tag).
pub const MAX_PACKET_SIZE: usize = 1500 + AEAD_TAG_LEN;

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// WireGuard uses a 64-bit counter as nonce (padded to 96 bits with 4 zero bytes).
/// AAD is additional authenticated data (empty for transport, used in handshake).
pub fn seal(key: &[u8; 32], counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = build_nonce(counter);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failed")
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
///
/// Returns None if authentication fails (wrong key, tampered data, wrong nonce).
pub fn open(key: &[u8; 32], counter: u64, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = build_nonce(counter);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

/// Encrypt with XChaCha20-Poly1305 (24-byte nonce). Used for cookie encryption.
pub fn xseal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .expect("xchacha encryption failed")
}

/// Decrypt with XChaCha20-Poly1305 (24-byte nonce). Used for cookie decryption.
pub fn xopen(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(xnonce, Payload { msg: ciphertext, aad })
        .ok()
}

/// Encrypt in place: copies plaintext to buf, appends tag. Returns total length.
/// buf must be at least plaintext.len() + AEAD_TAG_LEN bytes.
/// Zero allocations.
pub fn seal_to(key: &[u8; 32], counter: u64, plaintext: &[u8], buf: &mut [u8]) -> usize {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = build_nonce(counter);
    let len = plaintext.len();
    buf[..len].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut buf[..len])
        .expect("encryption failed");
    buf[len..len + AEAD_TAG_LEN].copy_from_slice(&tag);
    len + AEAD_TAG_LEN
}

/// Decrypt in place: decrypts ciphertext in buf, returns plaintext length.
/// buf contains ciphertext + tag on input, plaintext on output.
/// Zero allocations.
pub fn open_to(key: &[u8; 32], counter: u64, buf: &mut [u8], ct_len: usize) -> Option<usize> {
    if ct_len < AEAD_TAG_LEN {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = build_nonce(counter);
    let pt_len = ct_len - AEAD_TAG_LEN;
    let (data, tag_bytes) = buf[..ct_len].split_at_mut(pt_len);
    let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(&nonce, &[], data, tag)
        .ok()?;
    Some(pt_len)
}

/// WireGuard nonce: 4 bytes of zeros || 8 bytes little-endian counter.
fn build_nonce(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open() {
        let key = [0x42u8; 32];
        let plaintext = b"wireguard is elegant";
        let aad = b"";

        let ciphertext = seal(&key, 0, aad, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);

        let decrypted = open(&key, 0, aad, &ciphertext).expect("decryption failed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];

        let ciphertext = seal(&key, 0, b"", b"secret");
        assert!(open(&wrong_key, 0, b"", &ciphertext).is_none());
    }

    #[test]
    fn wrong_counter_fails() {
        let key = [0x42u8; 32];
        let ciphertext = seal(&key, 0, b"", b"secret");
        assert!(open(&key, 1, b"", &ciphertext).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let mut ciphertext = seal(&key, 0, b"", b"secret");
        ciphertext[0] ^= 0xff;
        assert!(open(&key, 0, b"", &ciphertext).is_none());
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let ciphertext = seal(&key, 0, b"correct", b"secret");
        assert!(open(&key, 0, b"wrong", &ciphertext).is_none());
    }
}
