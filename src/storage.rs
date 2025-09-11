//! Storage backend traits and implementations

use crate::{key::VersionedKey, KeyId, KeyMetadata, KeyState, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Trait for key storage backends
pub trait KeyStore: Send + Sync {
    /// Store a versioned key
    fn store(&mut self, key: VersionedKey) -> Result<()>;

    /// Retrieve a key by ID
    fn retrieve(&self, id: &KeyId) -> Result<VersionedKey>;

    /// Delete a key
    fn delete(&mut self, id: &KeyId) -> Result<()>;

    /// List all kety IDs
    fn list(&self) -> Result<Vec<KeyId>>;

    /// Update key metadata
    fn update_metadata(&mut self, id: &KeyId, metadata: KeyMetadata) -> Result<()>; 

    /// Find keys by state
    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>>;
}

/// Trair for persistent storage backends
pub trait PersistentStorage: KeyStore {
    /// Flush any pending writes to persistent storage
    fn flush(&mut self) -> Result<()>;

    /// Load keys from persistent storage
    fn load(&mut self) -> Result<()>;

    /// Get the storage location/path
    fn location(&self) -> &str;
}

/// Trait for encrypted storage
pub trait EncrytedStore: KeyStore {
    /// Initiate the store with a master key
    /// 
    /// TODO: Implement master key derivation and rotation
    fn init_with_password(&mut self, password: &[u8]) -> Result<()>; 

    /// Re-encrypt all keys with a new master key
    fn rekey(&mut self, new_password: &[u8]) -> Result<()>;

    /// Check if the store is unlocked
    fn is_unlocked(&self) -> bool;
}

/// In-memory key store (for testing/development)
/// 
/// TODO: Replace with our actual implementation later on
pub struct MemoryStore {
    keys: Arc<RwLock<HashMap<KeyId, VersionedKey>>>,
}

impl MemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl KeyStore for MemoryStore {
    fn store(&mut self, key: VersionedKey) -> Result<()> {
        todo!("implement memory store")
    }

    fn retrieve(&self, id: &KeyId) -> Result<VersionedKey> {
        todo!("implement memory store")
    }

    fn delete(&mut self, id: &KeyId) -> Result<()> {
        todo!("implement memory store")
    }

    fn list(&self) -> Result<Vec<KeyId>> {
        todo!("implement memory store")
    }

    fn update_metadata(&mut self, id: &KeyId, metadata: KeyMetadata) -> Result<()> {
        todo!("implement memory store")
    }

    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        todo!("implement memory store")
    }
}

/// Configuration for file-based storage
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to storage location (file, directory, etc.)
    pub path: Option<String>,
    /// Enable encryption at rest
    pub encrypted: bool,
    /// Enable compresssion
    pub compressed: bool,
    /// Maximum number of keys to cache in memory
    pub cache_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            encrypted: false,
            compressed: false,
            cache_size: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert!(config.encrypted);
        assert!(!config.compressed);
    }
}