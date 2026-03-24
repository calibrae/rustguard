use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A static (long-lived) X25519 secret key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StaticSecret(x25519_dalek::StaticSecret);

/// An ephemeral X25519 secret key. Single use, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSecret(x25519_dalek::StaticSecret);

/// An X25519 public key. 32 bytes on the wire.
/// Uses constant-time comparison to prevent timing side-channels.
#[derive(Clone, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for PublicKey {}

/// Result of a DH operation. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl StaticSecret {
    /// Generate a random static key using the provided RNG.
    pub fn random_from_rng(rng: &mut impl CryptoRngCore) -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(rng))
    }

    /// Generate a random static key using OS RNG.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let shared = self.0.diffie_hellman(&their_public.0);
        SharedSecret(shared.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl EphemeralSecret {
    /// Generate a random ephemeral key using the provided RNG.
    pub fn random_from_rng(rng: &mut impl CryptoRngCore) -> Self {
        // We use StaticSecret under the hood because x25519_dalek's
        // EphemeralSecret consumes itself on DH, which doesn't work
        // for WireGuard where we need the ephemeral for multiple DH ops.
        Self(x25519_dalek::StaticSecret::random_from_rng(rng))
    }

    /// Generate a random ephemeral key using OS RNG.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng))
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let shared = self.0.diffie_hellman(&their_public.0);
        SharedSecret(shared.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_exchange_produces_shared_secret() {
        let alice_secret = StaticSecret::random();
        let alice_public = alice_secret.public_key();

        let bob_secret = StaticSecret::random();
        let bob_public = bob_secret.public_key();

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn ephemeral_dh_works() {
        let eph = EphemeralSecret::random();
        let static_key = StaticSecret::random();

        let shared1 = eph.diffie_hellman(&static_key.public_key());
        let shared2 = static_key.diffie_hellman(&eph.public_key());

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn public_key_roundtrip() {
        let secret = StaticSecret::random();
        let pubkey = secret.public_key();
        let bytes = *pubkey.as_bytes();
        let restored = PublicKey::from_bytes(bytes);
        assert_eq!(pubkey, restored);
    }
}
