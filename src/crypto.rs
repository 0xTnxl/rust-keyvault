//! Cryptographic primitives and trait abstractions.
//!
//! This module provides the core cryptographic building blocks for rust-keyvault, including:
//! - AEAD (Authenticated Encryption with Associated Data) implementations
//! - Key generation with cryptographically secure random number generators
//! - Nonce generation strategies
//! - Runtime-polymorphic cryptographic operations
//!
//! # Architecture
//!
//! The module uses trait-based abstraction to allow for:
//! - Algorithm flexibility (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM)
//! - Testing with deterministic RNGs
//! - Future extensibility for new algorithms
//!
//! # Examples
//!
//! ## Basic AEAD Encryption
//!
//! ```
//! use rust_keyvault::{Algorithm, key::SecretKey};
//! use rust_keyvault::crypto::{RuntimeAead, RandomNonceGenerator, AEAD, NonceGenerator};
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//!
//! # fn main() -> rust_keyvault::Result<()> {
//! // Generate a key
//! let key = SecretKey::generate(Algorithm::XChaCha20Poly1305)?;
//!
//! // Create AEAD instance
//! let aead = RuntimeAead;
//!
//! // Generate a nonce
//! let mut nonce_gen = RandomNonceGenerator::new(
//!     ChaCha20Rng::from_entropy(),
//!     24 // XChaCha20 nonce size
//! );
//! let nonce = nonce_gen.generate_nonce(b"message-id")?;
//!
//! // Encrypt
//! let plaintext = b"Secret message";
//! let aad = b"public metadata";
//! let ciphertext = aead.encrypt(&key, &nonce, plaintext, aad)?;
//!
//! // Decrypt
//! let decrypted = aead.decrypt(&key, &nonce, &ciphertext, aad)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Nonce Reuse
//!
//! **CRITICAL**: Never reuse a nonce with the same key. Nonce reuse completely breaks
//! the security of AEAD schemes:
//! - For 12-byte nonces (ChaCha20, AES-GCM): Use counters or careful coordination
//! - For 24-byte nonces (XChaCha20): Random generation is safe
//!
//! ## Key Generation
//!
//! All key generation uses ChaCha20Rng seeded from system entropy, providing
//! cryptographically secure randomness suitable for key material.

use crate::{Error, key::SecretKey, Algorithm, Result};
use rand_core::{CryptoRng, RngCore};
use aead::{Aead, KeyInit, Payload, generic_array::typenum::U12};
use chacha20poly1305::{
    ChaCha20Poly1305, 
    XChaCha20Poly1305, 
    Key as ChaChaKey, 
    Nonce as ChaChaNonce,
    XNonce,  
};
use aes_gcm::Aes256Gcm;

// Explicit concrete type aliases with explicit sizes
type AesKey = aes_gcm::Key<Aes256Gcm>;
type AesNonce = aes_gcm::Nonce<U12>;

/// Trait for cryptographically secure random number generators.
///
/// This trait extends [`RngCore`] and [`CryptoRng`] to provide an ergonomic interface
/// for filling buffers with cryptographically secure random bytes.
///
/// # Security
///
/// Implementations must provide cryptographically secure randomness suitable for
/// generating keys, nonces, salts, and other security-critical values.
///
/// # Examples
///
/// ```
/// use rust_keyvault::crypto::SecureRandom;
/// use rand_chacha::ChaCha20Rng;
/// use rand_core::SeedableRng;
///
/// let mut rng = ChaCha20Rng::from_entropy();
/// let mut buffer = [0u8; 32];
/// rng.fill_secure_bytes(&mut buffer).unwrap();
/// assert_ne!(buffer, [0u8; 32]); // Should be filled with random data
/// ```
pub trait SecureRandom: RngCore + CryptoRng {
    /// Fill a buffer with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the RNG fails to generate randomness (e.g., if the
    /// system entropy source is unavailable).
    fn fill_secure_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.try_fill_bytes(dest).map_err(|e| Error::crypto("fill_bytes", &format!("failed to fill secure bytes: {}", e)))?;
        Ok(())
    }
}

/// Trait for cryptographic key generation.
///
/// Provides methods for generating keys with optional parameters. Implementations
/// should use cryptographically secure random sources and support configurable
/// algorithms and key sizes.
///
/// # Examples
///
/// ```
/// use rust_keyvault::crypto::{KeyGenerator, SimpleSymmetricKeyGenerator, SecureRandom, KeyGenParams};
/// use rust_keyvault::Algorithm;
/// use rand_chacha::ChaCha20Rng;
/// use rand_core::SeedableRng;
///
/// # fn main() -> rust_keyvault::Result<()> {
/// let generator = SimpleSymmetricKeyGenerator;
/// let mut rng = ChaCha20Rng::from_entropy();
///
/// // Generate a key with default algorithm
/// let key = generator.generate(&mut rng)?;
///
/// // Generate a key with specific algorithm
/// let params = KeyGenParams {
///     algorithm: Algorithm::XChaCha20Poly1305,
///     seed: None,
///     key_size: None,
/// };
/// let key = generator.generate_with_params(&mut rng, params)?;
/// # Ok(())
/// # }
/// ```
pub trait KeyGenerator {
    /// The type of key this generator produces
    type Key;

    /// Generate a new key using default parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails (e.g., RNG failure).
    fn generate<R: SecureRandom>(&self, rng: &mut R) -> Result<Self::Key>;

    /// Generate a new key with specific parameters.
    ///
    /// Allows customization of the algorithm, key size, and optional seed material
    /// for deterministic generation (primarily for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the parameters are invalid or key generation fails.
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

/// Trait for AEAD (Authenticated Encryption with Associated Data) operations.
///
/// AEAD provides both confidentiality and authenticity in a single operation. It encrypts
/// the plaintext and authenticates both the ciphertext and additional associated data (AAD).
///
/// # Properties
///
/// - **Confidentiality**: Plaintext is hidden from unauthorized parties
/// - **Authenticity**: Tampering with ciphertext or AAD is detectable
/// - **Nonce-Based**: Each encryption requires a unique nonce
/// - **Associated Data**: Public metadata can be authenticated without encryption
///
/// # Nonce Requirements
///
/// **CRITICAL**: Nonces must NEVER be reused with the same key. Nonce reuse completely
/// breaks AEAD security, potentially revealing plaintexts and auth tags.
///
/// Safe nonce strategies:
/// - **24-byte nonces** (XChaCha20): Generate randomly
/// - **12-byte nonces** (ChaCha20, AES-GCM): Use counters or carefully managed sequences
///
/// # Examples
///
/// ```
/// use rust_keyvault::{Algorithm, key::SecretKey};
/// use rust_keyvault::crypto::{RuntimeAead, RandomNonceGenerator, AEAD, NonceGenerator};
/// use rand_chacha::ChaCha20Rng;
/// use rand_core::SeedableRng;
///
/// # fn main() -> rust_keyvault::Result<()> {
/// let key = SecretKey::generate(Algorithm::XChaCha20Poly1305)?;
/// let aead = RuntimeAead;
/// let mut nonce_gen = RandomNonceGenerator::new(ChaCha20Rng::from_entropy(), 24);
///
/// // Encrypt with AAD
/// let plaintext = b"Secret message";
/// let aad = b"user_id=12345"; // Authenticated but not encrypted
/// let nonce = nonce_gen.generate_nonce(b"msg-001")?;
/// let ciphertext = aead.encrypt(&key, &nonce, plaintext, aad)?;
///
/// // Decrypt and verify
/// let decrypted = aead.decrypt(&key, &nonce, &ciphertext, aad)?;
/// assert_eq!(decrypted, plaintext);
///
/// // Tampering detection - wrong AAD fails
/// let wrong_aad = b"user_id=99999";
/// assert!(aead.decrypt(&key, &nonce, &ciphertext, wrong_aad).is_err());
/// # Ok(())
/// # }
/// ```
pub trait AEAD {
    /// Nonce size in bytes.
    ///
    /// This is the maximum nonce size supported. Some algorithms may support
    /// smaller nonces, but this defines the standard size.
    const NONCE_SIZE: usize;
    
    /// Authentication tag size in bytes.
    ///
    /// All current AEAD algorithms use 128-bit (16-byte) tags.
    const TAG_SIZE: usize;

    /// Encrypt plaintext with associated data.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key (must match the algorithm)
    /// * `nonce` - A unique nonce (MUST be unique for each encryption with this key)
    /// * `plaintext` - The data to encrypt
    /// * `associated_data` - Additional data to authenticate (not encrypted)
    ///
    /// # Returns
    ///
    /// The ciphertext, which includes the authentication tag appended at the end.
    /// The ciphertext length is `plaintext.len() + TAG_SIZE`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key size doesn't match the algorithm
    /// - The nonce size is incorrect for the algorithm
    /// - The encryption operation fails
    ///
    /// # Security
    ///
    /// The nonce MUST be unique for every encryption with the same key. Nonce reuse
    /// destroys the security of AEAD.
    fn encrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with associated data.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key used for encryption
    /// * `nonce` - The nonce used during encryption
    /// * `ciphertext` - The encrypted data (includes authentication tag)
    /// * `associated_data` - The AAD used during encryption (must match exactly)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext if authentication succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails (ciphertext or AAD was tampered with)
    /// - The key size doesn't match the algorithm
    /// - The nonce size is incorrect
    /// - The ciphertext is too short
    ///
    /// # Security
    ///
    /// This operation verifies the authentication tag before returning any plaintext.
    /// If authentication fails, the ciphertext and/or associated data has been tampered with.
    fn decrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Runtime-polymorphic AEAD adapter supporting multiple algorithms.
///
/// `RuntimeAead` provides a unified interface for AEAD operations across different
/// algorithms (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM). The specific
/// algorithm is determined at runtime based on the key's algorithm field.
///
/// # Supported Algorithms
///
/// - **ChaCha20-Poly1305**: 12-byte nonces, excellent performance
/// - **XChaCha20-Poly1305**: 24-byte nonces, safe for random nonce generation
/// - **AES-256-GCM**: 12-byte nonces, hardware-accelerated on supported CPUs
///
/// # Examples
///
/// ```
/// use rust_keyvault::{Algorithm, key::SecretKey};
/// use rust_keyvault::crypto::{RuntimeAead, RandomNonceGenerator, AEAD, NonceGenerator};
/// use rand_chacha::ChaCha20Rng;
/// use rand_core::SeedableRng;
///
/// # fn main() -> rust_keyvault::Result<()> {
/// // Works with any algorithm
/// let aead = RuntimeAead;
///
/// for algo in [Algorithm::ChaCha20Poly1305, Algorithm::XChaCha20Poly1305, Algorithm::Aes256Gcm] {
///     let key = SecretKey::generate(algo)?;
///     let nonce_size = algo.nonce_size().unwrap();
///     let mut nonce_gen = RandomNonceGenerator::new(ChaCha20Rng::from_entropy(), nonce_size);
///     let nonce = nonce_gen.generate_nonce(b"test")?;
///     
///     let ciphertext = aead.encrypt(&key, &nonce, b"test", b"aad")?;
///     let plaintext = aead.decrypt(&key, &nonce, &ciphertext, b"aad")?;
///     assert_eq!(plaintext, b"test");
/// }
/// # Ok(())
/// # }
/// ```
pub struct RuntimeAead;

impl RuntimeAead {
    fn check_key_len(key: &SecretKey, expected: usize) -> Result<()> {
        if key.expose_secret().len() != expected {
            return Err(Error::crypto(
                "key_validation",
                &format!(
                    "invalid key size: expected {}, got {}",
                    expected,
                    key.expose_secret().len()
                )
            ));
        }
        Ok(())
    }
}

impl crate::crypto::AEAD for RuntimeAead {
    // Maximum nonce size (XChaCha20Poly1305 uses 24 bytes, others use 12)
    const NONCE_SIZE: usize = 24;
    const TAG_SIZE: usize = 16;

    fn encrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Note: Each algorithm validates its own nonce size
        match key.algorithm() {
            Algorithm::ChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 12 {
                    return Err(Error::crypto("nonce_validation", &format!("ChaCha20Poly1305 requires 12-byte nonce, got {}", nonce.len())));
                }
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                // annotate nonce type to help type inference
                let n: &ChaChaNonce = ChaChaNonce::from_slice(nonce);
                cipher
                    .encrypt(n, Payload { msg: plaintext, aad: associated_data })
                    .map_err(|e| Error::crypto("encrypt", &format!("ChaCha20-Poly1305 encryption failed: {}", e)))
            }
            Algorithm::XChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 24 {
                    return Err(Error::crypto("nonce_validation", &format!("XChaCha20Poly1305 requires 24-byte nonce, got {}", nonce.len())));
                }
                let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                let n: &XNonce = XNonce::from_slice(nonce);
                cipher
                    .encrypt(n, Payload { msg: plaintext, aad: associated_data })
                    .map_err(|e| Error::crypto("encrypt", &format!("XChaCha20-Poly1305 encryption failed: {}", e)))
            }
            Algorithm::Aes256Gcm => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 12 {
                    return Err(Error::crypto("nonce_validation", &format!("AES-256-GCM requires 12-byte nonce, got {}", nonce.len())));
                }
                let cipher = Aes256Gcm::new(AesKey::from_slice(key.expose_secret()));
                let n: &AesNonce = AesNonce::from_slice(nonce);
                cipher
                    .encrypt(n, Payload { msg: plaintext, aad: associated_data })
                    .map_err(|e| Error::crypto("encrypt", &format!("AES-256-GCM encryption failed: {}", e)))
            }
            alg => Err(Error::crypto("encrypt", &format!("algorithm {alg:?} not supported for AEAD"))),
        }
    }

    fn decrypt(
        &self,
        key: &SecretKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Note: Each algorithm validates its own nonce size
        match key.algorithm() {
            Algorithm::ChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 12 {
                    return Err(Error::crypto("nonce_validation", &format!("ChaCha20Poly1305 requires 12-byte nonce, got {}", nonce.len())));
                }
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                let n: &ChaChaNonce = ChaChaNonce::from_slice(nonce);
                cipher
                    .decrypt(n, Payload { msg: ciphertext, aad: associated_data })
                    .map_err(|e| Error::crypto("decrypt", &format!("ChaCha20-Poly1305 decryption failed: {}", e)))
            }
            Algorithm::XChaCha20Poly1305 => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 24 {
                    return Err(Error::crypto("nonce_validation", &format!("XChaCha20Poly1305 requires 24-byte nonce, got {}", nonce.len())));
                }
                let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key.expose_secret()));
                let n: &XNonce = XNonce::from_slice(nonce);
                cipher
                    .decrypt(n, Payload { msg: ciphertext, aad: associated_data })
                    .map_err(|e| Error::crypto("decrypt", &format!("XChaCha20-Poly1305 decryption failed: {}", e)))
            }
            Algorithm::Aes256Gcm => {
                Self::check_key_len(key, 32)?;
                if nonce.len() != 12 {
                    return Err(Error::crypto("nonce_validation", &format!("AES-256-GCM requires 12-byte nonce, got {}", nonce.len())));
                }
                let cipher = Aes256Gcm::new(AesKey::from_slice(key.expose_secret()));
                let n: &AesNonce = AesNonce::from_slice(nonce);
                cipher
                    .decrypt(n, Payload { msg: ciphertext, aad: associated_data })
                    .map_err(|e| Error::crypto("decrypt", &format!("AES-256-GCM decryption failed: {}", e)))
            }
            alg => Err(Error::crypto("decrypt", &format!("algorithm {alg:?} not supported for AEAD"))),
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
        // ChaCha20Poly1305 needs 12-byte nonces
        let mut nonce_gen = RandomNonceGenerator::new(
            ChaCha12Rng::seed_from_u64(123),
            12  // ChaCha20Poly1305 nonce size
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