#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod x25519;
mod aead;
mod blake2s;
mod tai64n;

pub use self::x25519::{StaticSecret, PublicKey, SharedSecret, EphemeralSecret};
pub use self::aead::{seal, open, seal_to, open_to, xseal, xopen, AEAD_TAG_LEN, MAX_PACKET_SIZE};
pub use self::blake2s::{hash, mac, hkdf};
pub use self::tai64n::Tai64n;

/// WireGuard protocol constants.
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";
