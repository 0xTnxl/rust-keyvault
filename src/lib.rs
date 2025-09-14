//! rust-keyvault: A secure key management library for Rust
//! 
//! This crate provides foundational abstraction for cryptographic key management,, 
//! focusing on security, correctness and composability.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use zeroize::{Zeroize, ZeroizeOnDrop}; 
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
use std::fmt;

pub mod error;
pub mod key;
pub mod storage;
pub mod crypto;

pub use error::{Error, Result};


/// A unique identifier for a cryptographic key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// Generate a new random KeyId
    pub fn generate() -> Result<Self> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        
        Ok(Self(bytes))
    }

    /// Create a KeyId from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the KeyId.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Generate a versioned KeyId based on a base ID and version
    pub fn generate_versioned(base_id: &KeyId, version: u32) -> Result<Self> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(base_id.as_bytes());
        hasher.update(version.to_le_bytes());
        hasher.update(b"rust-keyvault-version");
        
        let hash = hasher.finalize();
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&hash[..16]);
        
        Ok(Self(id_bytes))
    }

    /// Check for same base id for any two keys
    pub fn same_base_id(_id1: &KeyId, _id2: &KeyId) -> bool {
        false
    }

    /// Generate a new random base KeyId for a key family
    pub fn generate_base() -> Result<Self> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);

        Ok(Self(bytes))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Represents the lifecycle state of a key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key has been generated but is not yet active.
    Pending,
    /// Key is currently active for all operations.
    Active,
    /// Key is being rotated out (new key active, this key is still valid).
    Rotating,
    /// Key is deprecated (valid for verification only), should not be used for new operations.
    Deprecated,
    /// Key has been revoked (should not be used at all).
    Revoked,
}

/// Metadata about a key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for the key
    pub id: KeyId,
    /// Base identifier for the key
    pub base_id: KeyId,
    /// Current state in the key lifecycle
    pub state: KeyState,
    /// When this key was created
    pub created_at: SystemTime,
    /// When this key expires (if applicable)
    pub expires_at: Option<SystemTime>,
    /// Algorithm this key is used with
    pub algorithm: Algorithm,
    /// Version number for rotation tracking
    pub version: u32,
}

/// Supported cryptographic algorithms
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
    /// AES-256-GCM AEAD
    Aes256Gcm,
    /// Ed25519 signature
    Ed25519,
    /// X25519 key exchange
    X25519,
}

impl Algorithm {
    /// Get the key size in bytes for the algorithm
    pub const fn key_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 | Self::Aes256Gcm => 32,
            Self::Ed25519 | Self::X25519 => 32,
        }
    }

    /// Check if this algorithm is for symmetric encrytion
    pub const fn is_symmetric(&self) -> bool {
        matches!(self, Self::ChaCha20Poly1305 | Self::Aes256Gcm)
    } 
}

impl Zeroize for Algorithm {
    fn zeroize(&mut self) {
        *self = Algorithm::ChaCha20Poly1305;
    }
}

impl ZeroizeOnDrop for Algorithm {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(Algorithm::ChaCha20Poly1305.key_size(), 32);
        assert!(Algorithm::ChaCha20Poly1305.is_symmetric());
        assert!(!Algorithm::Ed25519.is_symmetric());
    }
}