//! Error types for rust-keyvault

use thiserror::Error;

/// Custom `Result` type 
pub type Result<T> = std::result::Result<T, Error>; 

/// `rust-keyvault` error module
#[derive(Debug, Error)]
pub enum Error {
    /// Key not found in storage
    #[error("key not found: {0:?}")]
    KeyNotFound(crate::KeyId),

    /// Key has expired
    #[error("key has expired")]
    KeyExpired,

    /// Key is in the wrong state for requested operation
    #[error("invalid key state: {0}")]
    InvalidKeyState(String),

    /// Cryptographic operation failed
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    /// Storage backend failed
    #[error("storage error: {0}")]
    StorageError(String),

    /// Insufficient entropy available
    #[error("insufficient entropy")]
    InsufficientEntropy,

    /// Key rotation failed
    #[error("rotation failed: {0}")]
    RotationFailed(String),

    /// Serialization/deserilization error
    #[error("serialisation error: {0}")]
    SerializationError(String),

    /// Generic I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl Error {
    /// Create a crypto error with a message
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Self::CryptoError(msg.into())
    }

    /// Create a storage error with a message
    pub fn storage<S: Into<String>>(msg: S) -> Self {
        Self::StorageError(msg.into())
    }
}