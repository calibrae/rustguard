//! Enrollment protocol messages.
//!
//! The enrollment channel is encrypted with a symmetric key derived from
//! the shared enrollment token. This prevents passive observers from
//! learning public keys, but the real security is the Noise_IK handshake
//! that follows — the token just gates who can enroll.
//!
//! Wire format:
//!   EnrollRequest:  magic(4) + nonce(24) + encrypted(32 pubkey) + tag(16) = 76 bytes
//!   EnrollResponse: magic(4) + nonce(24) + encrypted(32 pubkey + 4 ip + 1 prefix) + tag(16) = 81 bytes

use rustguard_crypto as crypto;

const ENROLL_REQUEST_MAGIC: [u8; 4] = [0x52, 0x47, 0x45, 0x01]; // "RGE\x01"
const ENROLL_RESPONSE_MAGIC: [u8; 4] = [0x52, 0x47, 0x45, 0x02]; // "RGE\x02"

pub const ENROLL_REQUEST_SIZE: usize = 76;
pub const ENROLL_RESPONSE_SIZE: usize = 81;

/// Derive an encryption key from the enrollment token.
/// Uses BLAKE2s hash so the raw token never appears on the wire.
pub fn derive_token_key(token: &str) -> [u8; 32] {
    crypto::hash(&[b"rustguard-enroll-v1", token.as_bytes()])
}

/// Build an enrollment request.
pub fn build_request(token_key: &[u8; 32], our_pubkey: &[u8; 32]) -> [u8; ENROLL_REQUEST_SIZE] {
    let nonce = random_nonce();
    let encrypted = crypto::xseal(token_key, &nonce, &ENROLL_REQUEST_MAGIC, our_pubkey);

    let mut buf = [0u8; ENROLL_REQUEST_SIZE];
    buf[0..4].copy_from_slice(&ENROLL_REQUEST_MAGIC);
    buf[4..28].copy_from_slice(&nonce);
    buf[28..76].copy_from_slice(&encrypted); // 32 + 16 tag = 48
    buf
}

/// Parse and decrypt an enrollment request.
/// Returns the client's public key.
pub fn parse_request(token_key: &[u8; 32], buf: &[u8]) -> Option<[u8; 32]> {
    if buf.len() < ENROLL_REQUEST_SIZE {
        return None;
    }
    if buf[0..4] != ENROLL_REQUEST_MAGIC {
        return None;
    }
    let nonce: [u8; 24] = buf[4..28].try_into().ok()?;
    let ciphertext = &buf[28..76];
    let plaintext = crypto::xopen(token_key, &nonce, &ENROLL_REQUEST_MAGIC, ciphertext)?;
    plaintext.try_into().ok()
}

/// Enrollment response payload: server pubkey + assigned IPv4 + prefix length.
pub struct EnrollmentOffer {
    pub server_pubkey: [u8; 32],
    pub assigned_ip: std::net::Ipv4Addr,
    pub prefix_len: u8,
}

/// Build an enrollment response.
pub fn build_response(token_key: &[u8; 32], offer: &EnrollmentOffer) -> [u8; ENROLL_RESPONSE_SIZE] {
    let mut plaintext = [0u8; 37]; // 32 + 4 + 1
    plaintext[0..32].copy_from_slice(&offer.server_pubkey);
    plaintext[32..36].copy_from_slice(&offer.assigned_ip.octets());
    plaintext[36] = offer.prefix_len;

    let nonce = random_nonce();
    let encrypted = crypto::xseal(token_key, &nonce, &ENROLL_RESPONSE_MAGIC, &plaintext);

    let mut buf = [0u8; ENROLL_RESPONSE_SIZE];
    buf[0..4].copy_from_slice(&ENROLL_RESPONSE_MAGIC);
    buf[4..28].copy_from_slice(&nonce);
    buf[28..81].copy_from_slice(&encrypted); // 37 + 16 tag = 53
    buf
}

/// Parse and decrypt an enrollment response.
pub fn parse_response(token_key: &[u8; 32], buf: &[u8]) -> Option<EnrollmentOffer> {
    if buf.len() < ENROLL_RESPONSE_SIZE {
        return None;
    }
    if buf[0..4] != ENROLL_RESPONSE_MAGIC {
        return None;
    }
    let nonce: [u8; 24] = buf[4..28].try_into().ok()?;
    let ciphertext = &buf[28..81];
    let plaintext = crypto::xopen(token_key, &nonce, &ENROLL_RESPONSE_MAGIC, ciphertext)?;
    if plaintext.len() != 37 {
        return None;
    }

    Some(EnrollmentOffer {
        server_pubkey: plaintext[0..32].try_into().ok()?,
        assigned_ip: std::net::Ipv4Addr::new(
            plaintext[32],
            plaintext[33],
            plaintext[34],
            plaintext[35],
        ),
        prefix_len: plaintext[36],
    })
}

fn random_nonce() -> [u8; 24] {
    let mut buf = [0u8; 24];
    getrandom::getrandom(&mut buf).expect("failed to get random bytes");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let key = derive_token_key("test-token");
        let pubkey = [0x42u8; 32];
        let wire = build_request(&key, &pubkey);
        let parsed = parse_request(&key, &wire).unwrap();
        assert_eq!(parsed, pubkey);
    }

    #[test]
    fn request_wrong_token_fails() {
        let key1 = derive_token_key("correct");
        let key2 = derive_token_key("wrong");
        let wire = build_request(&key1, &[0x42; 32]);
        assert!(parse_request(&key2, &wire).is_none());
    }

    #[test]
    fn response_roundtrip() {
        let key = derive_token_key("test-token");
        let offer = EnrollmentOffer {
            server_pubkey: [0x99u8; 32],
            assigned_ip: std::net::Ipv4Addr::new(10, 150, 0, 42),
            prefix_len: 24,
        };
        let wire = build_response(&key, &offer);
        let parsed = parse_response(&key, &wire).unwrap();
        assert_eq!(parsed.server_pubkey, [0x99u8; 32]);
        assert_eq!(parsed.assigned_ip, std::net::Ipv4Addr::new(10, 150, 0, 42));
        assert_eq!(parsed.prefix_len, 24);
    }

    #[test]
    fn tampered_request_rejected() {
        let key = derive_token_key("token");
        let mut wire = build_request(&key, &[0x42; 32]);
        wire[30] ^= 0xff;
        assert!(parse_request(&key, &wire).is_none());
    }
}
