use alloc::vec::Vec;

/// WireGuard message types on the wire.

pub const MSG_INITIATION: u32 = 1;
pub const MSG_RESPONSE: u32 = 2;
pub const MSG_COOKIE_REPLY: u32 = 3;
pub const MSG_TRANSPORT: u32 = 4;

/// Handshake Initiation (type 1) — 148 bytes total.
///
/// ```text
/// type        (4)  = 0x01000000 LE
/// sender      (4)  sender index
/// ephemeral   (32) initiator's ephemeral public key
/// static_enc  (48) AEAD(initiator's static public key) — 32 + 16 tag
/// timestamp   (28) AEAD(TAI64N timestamp) — 12 + 16 tag
/// mac1        (16) MAC over the above
/// mac2        (16) cookie MAC (zeros if no cookie)
/// ```
#[derive(Clone)]
pub struct Initiation {
    pub sender_index: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

pub const INITIATION_SIZE: usize = 148;

/// Handshake Response (type 2) — 92 bytes total.
///
/// ```text
/// type        (4)  = 0x02000000 LE
/// sender      (4)  responder's index
/// receiver    (4)  initiator's index (from initiation)
/// ephemeral   (32) responder's ephemeral public key
/// empty_enc   (16) AEAD(empty) — 0 + 16 tag
/// mac1        (16) MAC
/// mac2        (16) cookie MAC
/// ```
#[derive(Clone)]
pub struct Response {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

pub const RESPONSE_SIZE: usize = 92;

/// Transport Data (type 4).
///
/// ```text
/// type        (4)  = 0x04000000 LE
/// receiver    (4)  receiver's index
/// counter     (8)  nonce counter (LE)
/// payload     (N)  encrypted packet + 16 byte tag
/// ```
pub struct Transport {
    pub receiver_index: u32,
    pub counter: u64,
    pub payload: Vec<u8>,
}

/// Cookie Reply (type 3) — 64 bytes total.
///
/// ```text
/// type              (4)  = 0x03000000 LE
/// receiver          (4)  initiator's sender_index
/// nonce             (24) random XChaCha20 nonce
/// encrypted_cookie  (32) XChaCha20-Poly1305(cookie) — 16 + 16 tag
/// ```
#[derive(Clone)]
pub struct CookieReply {
    pub receiver_index: u32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

pub const COOKIE_REPLY_SIZE: usize = 64;

pub const TRANSPORT_HEADER_SIZE: usize = 16;

impl Initiation {
    pub fn to_bytes(&self) -> [u8; INITIATION_SIZE] {
        let mut buf = [0u8; INITIATION_SIZE];
        buf[0..4].copy_from_slice(&MSG_INITIATION.to_le_bytes());
        buf[4..8].copy_from_slice(&self.sender_index.to_le_bytes());
        buf[8..40].copy_from_slice(&self.ephemeral);
        buf[40..88].copy_from_slice(&self.encrypted_static);
        buf[88..116].copy_from_slice(&self.encrypted_timestamp);
        buf[116..132].copy_from_slice(&self.mac1);
        buf[132..148].copy_from_slice(&self.mac2);
        buf
    }

    pub fn from_bytes(buf: &[u8; INITIATION_SIZE]) -> Self {
        Self {
            sender_index: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            ephemeral: buf[8..40].try_into().unwrap(),
            encrypted_static: buf[40..88].try_into().unwrap(),
            encrypted_timestamp: buf[88..116].try_into().unwrap(),
            mac1: buf[116..132].try_into().unwrap(),
            mac2: buf[132..148].try_into().unwrap(),
        }
    }
}

impl Response {
    pub fn to_bytes(&self) -> [u8; RESPONSE_SIZE] {
        let mut buf = [0u8; RESPONSE_SIZE];
        buf[0..4].copy_from_slice(&MSG_RESPONSE.to_le_bytes());
        buf[4..8].copy_from_slice(&self.sender_index.to_le_bytes());
        buf[8..12].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[12..44].copy_from_slice(&self.ephemeral);
        buf[44..60].copy_from_slice(&self.encrypted_empty);
        buf[60..76].copy_from_slice(&self.mac1);
        buf[76..92].copy_from_slice(&self.mac2);
        buf
    }

    pub fn from_bytes(buf: &[u8; RESPONSE_SIZE]) -> Self {
        Self {
            sender_index: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            receiver_index: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            ephemeral: buf[12..44].try_into().unwrap(),
            encrypted_empty: buf[44..60].try_into().unwrap(),
            mac1: buf[60..76].try_into().unwrap(),
            mac2: buf[76..92].try_into().unwrap(),
        }
    }
}

impl CookieReply {
    pub fn to_bytes(&self) -> [u8; COOKIE_REPLY_SIZE] {
        let mut buf = [0u8; COOKIE_REPLY_SIZE];
        buf[0..4].copy_from_slice(&MSG_COOKIE_REPLY.to_le_bytes());
        buf[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[8..32].copy_from_slice(&self.nonce);
        buf[32..64].copy_from_slice(&self.encrypted_cookie);
        buf
    }

    pub fn from_bytes(buf: &[u8; COOKIE_REPLY_SIZE]) -> Self {
        Self {
            receiver_index: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            nonce: buf[8..32].try_into().unwrap(),
            encrypted_cookie: buf[32..64].try_into().unwrap(),
        }
    }
}

impl Transport {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TRANSPORT_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&MSG_TRANSPORT.to_le_bytes());
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.counter.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < TRANSPORT_HEADER_SIZE {
            return None;
        }
        Some(Self {
            receiver_index: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            counter: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            payload: buf[16..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiation_roundtrip() {
        let msg = Initiation {
            sender_index: 42,
            ephemeral: [1u8; 32],
            encrypted_static: [2u8; 48],
            encrypted_timestamp: [3u8; 28],
            mac1: [4u8; 16],
            mac2: [5u8; 16],
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0..4], MSG_INITIATION.to_le_bytes());
        let parsed = Initiation::from_bytes(&bytes);
        assert_eq!(parsed.sender_index, 42);
        assert_eq!(parsed.ephemeral, [1u8; 32]);
    }

    #[test]
    fn response_roundtrip() {
        let msg = Response {
            sender_index: 7,
            receiver_index: 42,
            ephemeral: [1u8; 32],
            encrypted_empty: [2u8; 16],
            mac1: [3u8; 16],
            mac2: [4u8; 16],
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0..4], MSG_RESPONSE.to_le_bytes());
        let parsed = Response::from_bytes(&bytes);
        assert_eq!(parsed.sender_index, 7);
        assert_eq!(parsed.receiver_index, 42);
    }

    #[test]
    fn transport_roundtrip() {
        let msg = Transport {
            receiver_index: 42,
            counter: 99,
            payload: vec![0xAA; 100],
        };
        let bytes = msg.to_bytes();
        let parsed = Transport::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.receiver_index, 42);
        assert_eq!(parsed.counter, 99);
        assert_eq!(parsed.payload.len(), 100);
    }
}
