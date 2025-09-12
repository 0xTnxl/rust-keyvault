//! Core cryptographic traits and primitives

use crate::{Error, key::SecretKey, Algorithm, Result};
use rand_core::{CryptoRng, RngCore};
use aead::{Aead, KeyInit, Payload, generic_array::typenum::U12};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use aes_gcm::Aes256Gcm;

// Explicit concrete tye aliases with explicit sizes
type AesKey = aes_gcm::Key<Aes256Gcm>;
type AesNonce = aes_gcm::Nonce<U12>;

/// Trait for random number generators suitable for cryptographic use
pub trait SecureRandom: RngCore + CryptoRng {
    /// Fill a buffer with cryptographically secure random bytes
    fn fill_secure_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.try_fill_bytes(dest).map_err(|e| Error::crypto(format!("failed to fill secure bytes: {}", e)))?;
        Ok(())
    }
}

/// Trait for key generation
pub trait KeyGenerator {
    /// The type of key this generator produces
    type Key;

    /// Generate a new key
    fn generate<R: SecureRandom>(&self, rng: &mut R) -> Result<Self::Key>;

    /// Generate a new key with specific parameters
    fn generate_with_params<R: SecureRandom>(
        &self, rng: &mut R, params: KeyGenParams,
    ) -> Result<Self::Key>;
}
/// A simple symmetric key generator implementation
pub struct SimpleSymmetricKeyGenerator;

impl KeyGenerator for SimpleSymmetricKeyGenerator {
    type Key = SecretKey;

    fn generate<R: SecureRandom>(&self, rng: &mut R) -> Result<Self::Key> {
        let algorithm = Algorithm::ChaCha20Poly1305; // default algorithm
        let key_len = algorithm.key_size();
        let mut buf = vec![0u8; key_len]; 
        rng.fill_secure_bytes(&mut buf)?;
        SecretKey::from_bytes(buf, algorithm)
    }

    fn generate_with_params<R: SecureRandom>(
            &self, rng: &mut R, params: KeyGenParams,
        ) -> Result<Self::Key> {
        let algorithm = params.algorithm;
        let key_len = params.key_size.unwrap_or(algorithm.key_size());
        let mut buf = vec![0u8; key_len];
        rng.fill_secure_bytes(&mut buf)?;
        SecretKey::from_bytes(buf, algorithm)
    }
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

/// Trait for AEAD (Authenticated Encryption with Associated Data)
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

/// Runtime AEAD adapter supporting ChaCha20-Poly1305 and AES-GCM
pub struct RuntimeAead;

impl RuntimeAead {
    fn check_key_len(key: &SecretKey, expected: usize) -> Result<()> {
        if key.expose_secret().len() != expected {
            return Err(Error::crypto(format!(
                "invalid key size: expected {}, got {}",
                expected,
                key.expose_secret().len()
            )));
        }
        Ok(())
    }
}

impl crate::crypto::AEAD for RuntimeAead {
    // both algorithms use a 12-byte nonce and 16-byte tag
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    fn encrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::crypto(format!("invalid nonce length: expected {}", Self::NONCE_SIZE)));
        }

        match key.algorithm() {
            Algorithm::ChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                // annotate nonce type to help type inference
                let n: &ChaChaNonce = ChaChaNonce::from_slice(nonce);
                cipher
                    .encrypt(n, Payload { msg: plaintext, aad: associated_data })
                    .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 encryption failed: {}", e))) // produce concrete String
            }
            Algorithm::Aes256Gcm => {
                Self::check_key_len(key, 32)?;
                let cipher = Aes256Gcm::new(AesKey::from_slice(key.expose_secret()));
                let n: &AesNonce = AesNonce::from_slice(nonce);
                cipher
                    .encrypt(n, Payload { msg: plaintext, aad: associated_data })
                    .map_err(|e| Error::crypto(format!("AES-256-GCM encryption failed: {}", e)))
            }
            alg => Err(Error::crypto(format!("algorithm {:?} not supported for AEAD", alg))),
        }
    }

    fn decrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::crypto(format!("invalid nonce length: expected {}", Self::NONCE_SIZE)));
        }

        match key.algorithm() {
            Algorithm::ChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                let n: &ChaChaNonce = ChaChaNonce::from_slice(nonce);
                cipher
                    .decrypt(n, Payload { msg: ciphertext, aad: associated_data })
                    .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 decryption failed: {}", e)))
            }
            Algorithm::Aes256Gcm => {
                Self::check_key_len(key, 32)?;
                let cipher = Aes256Gcm::new(AesKey::from_slice(key.expose_secret()));
                let n: &AesNonce = AesNonce::from_slice(nonce);
                cipher
                    .decrypt(n, Payload { msg: ciphertext, aad: associated_data })
                    .map_err(|e| Error::crypto(format!("AES-256-GCM decryption failed: {}", e)))
            }
            alg => Err(Error::crypto(format!("algorithm {:?} not supported for AEAD", alg))),
        }
    }
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

/// Nonce generator using a cryptographically secure RNG
pub struct RandomNonceGenerator<R: SecureRandom> {
    rng: R,
    nonce_size: usize,
}

/// Random nonce generator implementation
impl<R: SecureRandom> RandomNonceGenerator<R> {
    /// Create a new random nonce generator
    pub fn new(rng: R, nonce_size: usize) -> Self {
        Self { rng, nonce_size }
    } 
}

impl<R: SecureRandom> NonceGenerator for RandomNonceGenerator<R> {
    fn generate_nonce(&mut self, _message_id: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; self.nonce_size];
        self.rng.fill_secure_bytes(&mut nonce)?;
        Ok(nonce)
    }

    fn strategy(&self) -> NonceStrategy {
        NonceStrategy::Random
    }
}

/// Blanket implementation for any crypto RNG
impl<T> SecureRandom for T where T: RngCore + CryptoRng {}

/// Trait for constant-time operations
pub trait ConstantTime {
    /// Compare two byte slices in constant time
    fn ct_eq(&self, other: &[u8]) -> bool;

    /// Select between two values in constant time
    fn ct_select(condition: bool, a: Self, b: Self) -> Self where Self: Sized;
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

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

    #[test]
    fn test_end_to_end_aead() {
        // Create deterministic RNG for testing and generate a key
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let generator = SimpleSymmetricKeyGenerator;
        let key = generator.generate(&mut rng).unwrap();

        // Create AEAD and nonce generator
        let aead = RuntimeAead;
        let mut nonce_gen = RandomNonceGenerator::new(
            ChaCha12Rng::seed_from_u64(123),
            RuntimeAead::NONCE_SIZE
        );

        // Let's test the data
        let plaintext = b"Secret message for testing";
        let associated_data = b"public metadata";

        // Encrypt
        let nonce = nonce_gen.generate_nonce(b"msg_001").unwrap ();
        let ciphertext = aead.encrypt(&key, &nonce, plaintext, associated_data).unwrap();

        // Verify that the ciphertext is different from the plaintext
        assert_ne!(ciphertext.as_slice(), plaintext);

        // Decrypt and finally verify
        let decrypted = aead.decrypt(&key, &nonce, &ciphertext, associated_data).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}