//! Error types for rust-keyvault

use thiserror::Error;
use std::fmt;

/// Custom `Result` type 
pub type Result<T> = std::result::Result<T, Error>; 

/// Error codes for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Key not found (404-equivalent)
    KeyNotFound,
    /// Key expired (410-equivalent)
    KeyExpired,
    /// Invalid key state for operation
    InvalidKeyState,
    /// Cryptographic operation failed
    CryptoFailure,
    /// Storage backend error
    StorageFailure,
    /// Insufficient entropy
    InsufficientEntropy,
    /// Key rotation failed
    RotationFailure,
    /// Serialization/deserialization failed
    SerializationFailure,
    /// I/O error
    IoFailure,
    /// Authentication failed
    AuthenticationFailure,
    /// Configuration error
    ConfigurationError,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "KEY_NOT_FOUND"),
            Self::KeyExpired => write!(f, "KEY_EXPIRED"),
            Self::InvalidKeyState => write!(f, "INVALID_KEY_STATE"),
            Self::CryptoFailure => write!(f, "CRYPTO_FAILURE"),
            Self::StorageFailure => write!(f, "STORAGE_FAILURE"),
            Self::InsufficientEntropy => write!(f, "INSUFFICIENT_ENTROPY"),
            Self::RotationFailure => write!(f, "ROTATION_FAILURE"),
            Self::SerializationFailure => write!(f, "SERIALIZATION_FAILURE"),
            Self::IoFailure => write!(f, "IO_FAILURE"),
            Self::AuthenticationFailure => write!(f, "AUTHENTICATION_FAILURE"),
            Self::ConfigurationError => write!(f, "CONFIGURATION_ERROR"),
        }
    }
}

/// Context about what operation was being performed when error occurred
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// The operation that was being performed
    pub operation: String,
    /// Optional key ID involved
    pub key_id: Option<String>,
    /// Optional additional details
    pub details: Option<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new<S: Into<String>>(operation: S) -> Self {
        Self {
            operation: operation.into(),
            key_id: None,
            details: None,
        }
    }
    
    /// Add key ID to context
    pub fn with_key_id<S: Into<String>>(mut self, key_id: S) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
    
    /// Add details to context
    pub fn with_details<S: Into<String>>(mut self, details: S) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// `rust-keyvault` error type with enhanced context
#[derive(Debug, Error)]
pub enum Error {
    /// Key not found in storage
    #[error("key not found: {key_id} (operation: {operation})")]
    KeyNotFound {
        /// The ID of the key that was not found
        key_id: String,
        /// The operation that was attempting to access the key
        operation: String,
    },

    /// Key has expired
    #[error("key has expired: {key_id} (expired at: {expired_at:?})")]
    KeyExpired {
        /// The ID of the expired key
        key_id: String,
        /// When the key expired
        expired_at: std::time::SystemTime,
    },

    /// Key is in the wrong state for requested operation
    #[error("invalid key state: {state} for operation '{operation}' on key {key_id}")]
    InvalidKeyState {
        /// The ID of the key with invalid state
        key_id: String,
        /// The current state of the key
        state: String,
        /// The operation that was attempted
        operation: String,
    },

    /// Cryptographic operation failed
    #[error("cryptographic error during {operation}: {message}")]
    CryptoError {
        /// The operation that was being performed when the error occurred
        operation: String,
        /// Detailed error message
        message: String,
        /// Optional key ID involved in the operation
        key_id: Option<String>,
    },

    /// Storage backend failed
    #[error("storage error during {operation}: {message}")]
    StorageError {
        /// The operation that was being performed when the error occurred
        operation: String,
        /// Detailed error message
        message: String,
        /// Optional filesystem path involved in the operation
        path: Option<String>,
    },

    /// Insufficient entropy available
    #[error("insufficient entropy for operation: {operation}")]
    InsufficientEntropy {
        /// The operation that required entropy
        operation: String,
    },

    /// Key rotation failed
    #[error("rotation failed for key {key_id}: {reason}")]
    RotationFailed {
        /// The ID of the key that failed to rotate
        key_id: String,
        /// The reason rotation failed
        reason: String,
    },

    /// Serialization/deserialization error
    #[error("serialization error during {operation}: {message}")]
    SerializationError {
        /// The serialization operation that failed
        operation: String,
        /// Detailed error message
        message: String,
    },

    /// Generic I/O error with context
    #[error("I/O error during {operation}: {source}")]
    IoError {
        /// The I/O operation that failed
        operation: String,
        /// The underlying I/O error
        #[source]
        source: std::io::Error,
    },
    
    /// Authentication failed
    #[error("authentication failed: {reason}")]
    AuthenticationFailed {
        /// The reason authentication failed
        reason: String,
        /// Number of failed attempts, if tracked
        attempts: Option<u32>,
    },
    
    /// Configuration error
    #[error("configuration error: {message}")]
    ConfigurationError {
        /// Description of the configuration problem
        message: String,
    },
}

impl Error {
    /// Get the error code for programmatic handling
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::KeyNotFound { .. } => ErrorCode::KeyNotFound,
            Self::KeyExpired { .. } => ErrorCode::KeyExpired,
            Self::InvalidKeyState { .. } => ErrorCode::InvalidKeyState,
            Self::CryptoError { .. } => ErrorCode::CryptoFailure,
            Self::StorageError { .. } => ErrorCode::StorageFailure,
            Self::InsufficientEntropy { .. } => ErrorCode::InsufficientEntropy,
            Self::RotationFailed { .. } => ErrorCode::RotationFailure,
            Self::SerializationError { .. } => ErrorCode::SerializationFailure,
            Self::IoError { .. } => ErrorCode::IoFailure,
            Self::AuthenticationFailed { .. } => ErrorCode::AuthenticationFailure,
            Self::ConfigurationError { .. } => ErrorCode::ConfigurationError,
        }
    }
    
    /// Create a crypto error with context
    pub fn crypto<S: Into<String>>(operation: S, message: S) -> Self {
        Self::CryptoError {
            operation: operation.into(),
            message: message.into(),
            key_id: None,
        }
    }
    
    /// Create a crypto error with key context
    pub fn crypto_with_key<S: Into<String>>(operation: S, message: S, key_id: S) -> Self {
        Self::CryptoError {
            operation: operation.into(),
            message: message.into(),
            key_id: Some(key_id.into()),
        }
    }

    /// Create a storage error with context
    pub fn storage<S: Into<String>>(operation: S, message: S) -> Self {
        Self::StorageError {
            operation: operation.into(),
            message: message.into(),
            path: None,
        }
    }
    
    /// Create a storage error with path context
    pub fn storage_with_path<S: Into<String>>(operation: S, message: S, path: S) -> Self {
        Self::StorageError {
            operation: operation.into(),
            message: message.into(),
            path: Some(path.into()),
        }
    }
    
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::StorageError { .. } | Self::IoError { .. }
        )
    }
    
    /// Check if error is a authentication failure
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::AuthenticationFailed { .. })
    }
}

// Implement From for io::Error with context helper
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            operation: "unknown".to_string(),
            source: err,
        }
    }
}