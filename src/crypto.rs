//! Core cryptographic traits and primitives

use crate::{key::SecretKey, Algorithm, Result};
use rand_core::{CryptoRng, RngCore};

/// Trait for random number generators suitable for cryptographic use
pub trait SecureRandom: RngCore + CryptoRng {
    /// Fill a buffer with cryptographically secure random bytes
    /// 
    /// TODO: Implement with proper error handling for entropy
    fn fill_secure_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        todo!("Implement secure random generation")
    }
}

pub trait KeyGenerator {
    /// The type of key this generator produces
    type Key;

    /// Generate a new key
    fn generate<R: SecureRandom>(&self, rng: &mut R) -> Result<Self::Key>;

    fn generate_with_params<R: SecureRandom>(
        &self, rng: &mut R, params: KeyGenParams,
    ) -> Result<Self::Key>;
}

/// Parameters for key generation
#[derive(Debug, Clone)]
pub struct KeyGenParams {
    /// Algorithm to generate the key for
    pub algorithm: Algorithm,
    /// Optional seed materials (for deterministic generation)
    pub seed: Option<Vec<u8>>,
    /// Key size override (if algorithm supports multiple sizes)
    pub key_size: Option<usize>,
}

/// Trait for AEAD (Authenticated Encryptio with Associated Data)
pub trait AEAD {
    /// Nonce size in bytes
    const NONCE_SIZE: usize;
    /// Tag size in bytes
    const TAG_SIZE: usize;

    /// Encrypt palintext with associated data
    /// 
    /// TODO: Implement for ChaCha20-Poly1305 and AES-GCM
    fn encrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with associated data
    fn decrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Nonce generation strategies
#[derive(Debug, Clone, Copy)]
pub enum NonceStrategy {
    /// Random nonces (requires large nonce space)
    Random,
    /// Counter-based (requires persistent state)
    Counter, 
    /// Derived from message (requires unique messages)
    Synthetic,
}

/// Trait for nonce generation
pub trait NonceGenerator {
    /// Generate a nonce for encryption
    /// 
    /// CRITICAL: Nonce must never be reused with the same key to avoid breaking security
    fn generate_nonce(&mut self, message_id: &[u8]) -> Result<Vec<u8>>; 

    /// Get the strategy this generator uses
    fn strategy(&self) -> NonceStrategy;
}

pub trait ConstantTime {
    /// Compare two byte slices in constant time
    fn ct_eq(&self, other: &[u8]) -> bool;

    /// Select between two values in constant time
    fn ct_select(condition: bool, a: Self, b: Self) -> Self where Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_params() {
        let params = KeyGenParams {
            algorithm: Algorithm::Aes256Gcm,
            seed: None,
            key_size: Some(32),
        };
        assert_eq!(params.algorithm, Algorithm::Aes256Gcm);
        assert_eq!(params.key_size, Some(32));
        assert_eq!(params.seed, None);
    }
}