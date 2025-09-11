//! Key type defination and traits

use crate::{Algorithm, Error, KeyId, KeyMetadata, Result};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A cryptographic key is automatically zeroed on drop
#[derive(Zeroize, ZeroizeOnDrop)]
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
            return Err(Error::crypto(format!(
                "invalid key size: expected {}, got {}",
                algorithm.key_size(),
                bytes.len()
            )));
        }

        Ok(Self { bytes, algorithm })
    }

    /// Generate a new random key for the given algorithm
    /// 
    /// TODO: Implement using rand_core:RngCore
    pub fn generate(algorithm: Algorithm) -> Result<Self> {
        todo!("Implement key generation")
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
            return false
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
        matches!(self.metadata.state, crate::KeyState::Active | crate::KeyState::Rotating)
            && !self.is_expired()
    }

    /// Check is this key can be used for decryption/verification
    pub fn can_decrypt(&self) -> bool {
        matches!(self.metadata.state, crate::KeyState::Revoked) && !self.is_expired()
    }
}

/// Trait for the key derivation functions
pub trait KeyDerivation {
    /// Derive a key from the input material
    /// 
    /// TODO: We'll need to implement this for HKDF, PBKDF2, etc.
    fn derive(&self, input: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey>;
}

/// Trait for key wrapping/unwrapping
pub trait KeyWrap {
    /// Wrap a key for a secure storage or transport 
    fn wrap(&self, key: &SecretKey, kek: &SecretKey) -> Result<Vec<u8>>; 

    /// Unwrap a previously wrapped key
    fn unwrap(&self, wrapped: &[u8], kek: &SecretKey, algorithm: Algorithm) -> Result<SecretKey>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_zerioze() {
        // This test verifies that SecretKey is properly zeroed on drop
        // Later, we would verify that memory is actually zeroed
        let key = SecretKey::from_bytes(vec![0x42], Algorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(key.algorithm(), Algorithm::ChaCha20Poly1305);

        // The key would be zeroed on drop
    }
}
