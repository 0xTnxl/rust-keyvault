//! Key type definition and traits

use crate::{Algorithm, Error, KeyMetadata, Result};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A cryptographic key is automatically zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// The actual key material
    bytes: Vec<u8>,
    /// Algorithm this key is for
    algorithm: Algorithm,
}

impl SecretKey {
    /// Create a new SecretKey from raw bytes
    ///
    /// #Errors
    /// Return error if the key doesn't match the algorithm
    pub fn from_bytes(bytes: Vec<u8>, algorithm: Algorithm) -> Result<Self> {
        if bytes.len() != algorithm.key_size() {
            return Err(Error::crypto(
                "key_validation",
                &format!(
                    "invalid key size: expected {}, got {}",
                    algorithm.key_size(),
                    bytes.len()
                ),
            ));
        }

        Ok(Self { bytes, algorithm })
    }

    /// Generate a new random key for the given algorithm
    pub fn generate(algorithm: Algorithm) -> Result<Self> {
        use crate::crypto::{KeyGenerator, SimpleSymmetricKeyGenerator};
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        let mut rng = ChaCha20Rng::from_entropy();
        let generator = SimpleSymmetricKeyGenerator;
        let params = crate::crypto::KeyGenParams {
            algorithm,
            seed: None,
            key_size: None,
        };

        generator.generate_with_params(&mut rng, params)
    }

    /// Get the algorithm for this key
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Expose the raw key material
    ///
    /// #Safety
    /// This exposes the raw key raw materials. The caller is responsible
    /// for ensuring it doesn't leak
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Constant-time equality comparison
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.algorithm != other.algorithm {
            return false;
        }
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A versioned key with metadata
#[derive(Clone, Debug)]
pub struct VersionedKey {
    /// The secret key material
    pub key: SecretKey,
    /// Metadata about this key
    pub metadata: KeyMetadata,
}

impl VersionedKey {
    /// Check if this key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.metadata.expires_at {
            std::time::SystemTime::now() > expires_at
        } else {
            false
        }
    }

    /// Check if this key can be used for encryption/signing
    pub fn can_encrypt(&self) -> bool {
        matches!(
            self.metadata.state,
            crate::KeyState::Active | crate::KeyState::Rotating
        ) && !self.is_expired()
    }

    /// Check is this key can be used for decryption/verification
    pub fn can_decrypt(&self) -> bool {
        !matches!(self.metadata.state, crate::KeyState::Revoked) && !self.is_expired()
    }
}

/// Trait for the key derivation functions
///
/// Enables secure storage or transport of keys by encrypting them
pub trait KeyDerivation {
    /// Derive a key from the input material
    fn derive(&self, input: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey>;
}

/// Trait for key wrapping/unwrapping
pub trait KeyWrap {
    /// Wrap a key for a secure storage or transport
    fn wrap(&self, key: &SecretKey, kek: &SecretKey) -> Result<Vec<u8>>;

    /// Unwrap a previously wrapped key
    fn unwrap(&self, wrapped: &[u8], kek: &SecretKey, algorithm: Algorithm) -> Result<SecretKey>;
}

/// HKDF-SHA256 key derivation implementation
pub struct HkdfSha256;

impl KeyDerivation for HkdfSha256 {
    fn derive(&self, input: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
        let mut okm = vec![0u8; 32]; // 32 bytes for symmetric keys
        hkdf.expand(info, &mut okm)
            .map_err(|e| Error::crypto("hkdf_expand", &format!("HKDF expansion failed: {}", e)))?;

        SecretKey::from_bytes(okm, Algorithm::ChaCha20Poly1305)
    }
}

/// HKDF-SHA512 key derivation implementation for higher security
pub struct HkdfSha512;

impl KeyDerivation for HkdfSha512 {
    fn derive(&self, input: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey> {
        use hkdf::Hkdf;
        use sha2::Sha512;

        let hkdf = Hkdf::<Sha512>::new(Some(salt), input);
        let mut okm = vec![0u8; 32];
        hkdf.expand(info, &mut okm)
            .map_err(|e| Error::crypto("hkdf_expand", &format!("HKDF expansion failed: {}", e)))?;

        SecretKey::from_bytes(okm, Algorithm::ChaCha20Poly1305)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_zeroize() {
        // Test ChaCha2--Poly1305
        {
            let original_bytes = vec![0x42; 32];
            let key = SecretKey::from_bytes(original_bytes, Algorithm::ChaCha20Poly1305).unwrap();
            let _key_ptr = key.expose_secret().as_ptr();
            assert_eq!(key.expose_secret()[0], 0x42);

            drop(key);

            // We can't actually verify the memory that was zeroized here
            // because the memory may have been reused.  So basically, this
            // is more of a "does it panic" test and verification that zeroize is called properly
        }

        // Test AES-256-GCM
        {
            let key = SecretKey::from_bytes(vec![0x33; 32], Algorithm::Aes256Gcm).unwrap();
            assert_eq!(key.expose_secret().len(), 32);
            assert_eq!(key.algorithm(), Algorithm::Aes256Gcm);
        }

        // Test invalid keys sizes (should fail)
        {
            let result = SecretKey::from_bytes(vec![0x11; 1], Algorithm::ChaCha20Poly1305);
            assert!(result.is_err());

            let result = SecretKey::from_bytes(vec![0x11; 16], Algorithm::ChaCha20Poly1305);
            assert!(result.is_err());

            let result = SecretKey::from_bytes(vec![0x11; 64], Algorithm::ChaCha20Poly1305);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_hkdf_sha256_derivation() {
        let kdf = HkdfSha256;
        let input = b"input key material for testing";
        let salt = b"unique random salt";
        let info = b"application context info";

        // Test basic derivation
        let key1 = kdf.derive(input, salt, info).unwrap();
        assert_eq!(key1.expose_secret().len(), 32);
        assert_eq!(key1.algorithm(), Algorithm::ChaCha20Poly1305);

        // Test determinism - same inputs = same output
        let key2 = kdf.derive(input, salt, info).unwrap();
        assert!(key1.ct_eq(&key2));

        // Test different info = different output
        let key3 = kdf.derive(input, salt, b"different context").unwrap();
        assert!(!key1.ct_eq(&key3));

        // Test different salt = different output
        let key4 = kdf.derive(input, b"different salt", info).unwrap();
        assert!(!key1.ct_eq(&key4));
    }

    #[test]
    fn test_hkdf_sha512_derivation() {
        let kdf = HkdfSha512;
        let input = b"test input material";
        let salt = b"test salt";
        let info = b"test info";

        let key = kdf.derive(input, salt, info).unwrap();
        assert_eq!(key.expose_secret().len(), 32);

        // Verify SHA512 produces different output than SHA256
        let kdf256 = HkdfSha256;
        let key256 = kdf256.derive(input, salt, info).unwrap();
        assert!(!key.ct_eq(&key256));
    }

    #[test]
    fn test_hkdf_use_case_session_key() {
        // Realistic use case: derive multiple session keys from master secret
        let kdf = HkdfSha256;
        let master_secret = b"shared master secret from ECDH";
        let salt = b"session-2024-01-01";

        let encryption_key = kdf.derive(master_secret, salt, b"encryption-key").unwrap();
        let mac_key = kdf.derive(master_secret, salt, b"mac-key").unwrap();
        let iv_key = kdf.derive(master_secret, salt, b"iv-key").unwrap();

        // All keys should be different
        assert!(!encryption_key.ct_eq(&mac_key));
        assert!(!encryption_key.ct_eq(&iv_key));
        assert!(!mac_key.ct_eq(&iv_key));
    }
}
