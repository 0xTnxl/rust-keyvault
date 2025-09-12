//! rust-keyvault: A secure key management library for Rust
//! 
//! This crate provides foundational abstraction for cryptographic key management,, 
//! focusing on security, correctness, and composability.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::SystemTime;
use aead::generic_array::typenum::Zero;
use zeroize::{Zeroize, ZeroizeOnDrop}; 

pub mod error;
pub mod key;
pub mod storage;
pub mod crypto;

pub use error::{Error, Result};


/// A unique identifier for a cryptographic key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// Generates a new random KeyId.
    /// 
    /// TODO: Implement using rand_core::RngCore for secure randomness.
    pub fn generate() -> Result<Self> {
        todo!("Implement random ID generation")
    }

    /// Create a KeyId from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the KeyId.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
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