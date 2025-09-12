//! Storage backend traits and implementations

use crate::{key::VersionedKey, KeyId, KeyMetadata, KeyState, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Deserialize, Serialize};

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

/// Trait for persistent storage backends
pub trait PersistentStorage: KeyStore {
    /// Flush any pending writes to persistent storage
    fn flush(&mut self) -> Result<()>;

    /// Load keys from persistent storage
    fn load(&mut self) -> Result<()>;

    /// Get the storage location/path
    fn location(&self) -> &str;
}

/// Serializable wrapper for persisted keys (excludes secret material)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedKey {
    /// Key metadata
    metadata: KeyMetadata,
    /// Encrypted key material (as bytes)
    encrypted_key: Vec<u8>,
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
        let key_id = key.metadata.id.clone();
        let mut keys = self.keys.write().map_err(|_| crate::Error::storage("lock poisoned"))?;
        keys.insert(key_id, key);
        Ok(())
    }

    fn retrieve(&self, id: &KeyId) -> Result<VersionedKey> {
        let keys = self.keys.read().map_err(|_| crate::Error::storage("lock poisoned"))?;
        keys.get(id)
            .cloned()
            .ok_or_else(|| crate::Error::storage(format!("key not found: {:?}", id)))
    }

    fn delete(&mut self, id: &KeyId) -> Result<()> {
        let mut keys = self.keys.write().map_err(|_| crate::Error::storage("lock poisoned"))?;
        keys.remove(id)
            .ok_or_else(|| crate::Error::storage(format!("key not found: {:?}", id)))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyId>> {
        let keys = self.keys.read().map_err(|_| crate::Error::storage("lock poisoned"))?;
        Ok(keys.keys().cloned().collect())
    }

    fn update_metadata(&mut self, id: &KeyId, metadata: KeyMetadata) -> Result<()> {
        let mut keys = self.keys.write().map_err(|_| crate::Error::storage("lock poisoned"))?;
        if let Some(versioned_key) = keys.get_mut(id) {
            versioned_key.metadata = metadata;
            Ok(())
        } else {
            Err(crate::Error::storage(format!("key not found: {:?}", id)))
        }
    }

    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        let keys = self.keys.read().map_err(|_| crate::Error::storage("lock poisoned"))?;
        Ok(keys
            .iter()
            .filter(|(_, versioned_key)| versioned_key.metadata.state == state)
            .map(|(id, _)| id.clone())
            .collect())
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

/// File-based key store with optional encryption
pub struct FileStore {
    /// Directory path for key storage
    path: PathBuf,
    /// In-memory cache of loaded keys
    keys: HashMap<KeyId, VersionedKey>,
    /// Configuration
    config: StorageConfig,
    /// Master key for encryption (optional, i.e. if enabled)
    master_key: Option<crate::key::SecretKey>,
}

impl FileStore {
    /// Create a new FileStore at the given path
    pub fn new<P: AsRef<Path>>(path: P, config: StorageConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Create the directory if it does not exists
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }

        let mut store = Self {
            path,
            keys: HashMap::new(),
            config,
            master_key: None,
        };

        // Load existing keys
        store.load()?;

        Ok(store)
    }

    /// Set master key for encryption
    pub fn set_master_key(&mut self, key: crate::key::SecretKey) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage("encryption not enabled in config"));
        }
        self.master_key = Some(key); 
        Ok(())
    }

    /// Get the file path for a key ID
    fn key_path(&self, id: &KeyId) -> PathBuf {
        let filename = format!("{:?}.json", id);
        self.path.join(filename)
    }

    /// Serialize the key and optionally encrypt a key
    fn serialize_key(&self, key: &VersionedKey) -> Result<Vec<u8>> {
        let key_bytes = key.key.expose_secret().to_vec();

        let encrypted_key = if self.config.encrypted {
            if let Some(_master_key) = &self.master_key {
                // TODO: We'd need to implement actual encryption using AEAD
                // For now, we'll just store plaintext with a warning
                eprintln!("WARNING: Encryption requested but not yet implemented");
                key_bytes
            } else {
                return Err(crate::Error::storage("encryption enabled but no master key set"));
            }
        } else {
            key_bytes
        };

        let persisted = PersistedKey {
            metadata: key.metadata.clone(),
            encrypted_key,
        };

        serde_json::to_vec(&persisted)
            .map_err(|e| crate::Error::storage(format!("serilization failed: {}", e))) 
    }
    /// Deserialize and optionally decrypt a key
    fn deserialize_key(&self, data: &[u8]) -> Result<VersionedKey> {
        let persisted: PersistedKey = serde_json::from_slice(data)
            .map_err(|e| crate::Error::storage(format!("deserialization failed: {}", e)))?;
        
        let key_bytes = if self.config.encrypted {
            if let Some(_master_key) = &self.master_key {
                // TODO: We'll also need to implement actual decryption later 
                eprintln!("WARNING: Decryption requested but not yet implemented");
                persisted.encrypted_key
            } else {
                return Err(crate::Error::storage("encrypted key but no master key available"));
            }
        } else {
            persisted.encrypted_key
        };
        
        let secret_key = crate::key::SecretKey::from_bytes(key_bytes, persisted.metadata.algorithm)?;
        
        Ok(VersionedKey {
            key: secret_key,
            metadata: persisted.metadata,
        })
    }
}

impl KeyStore for FileStore {
    fn store(&mut self, key: VersionedKey) -> Result<()> {
        let key_id = key.metadata.id.clone();
        let key_path = self.key_path(&key_id);
        
        // Serialize to bytes
        let data = self.serialize_key(&key)?;
        
        // Write to file
        fs::write(&key_path, data)?;
        
        // Update in-memory cache
        self.keys.insert(key_id, key);
        
        Ok(())
    }
    
    fn retrieve(&self, id: &KeyId) -> Result<VersionedKey> {
        // Check cache first
        if let Some(key) = self.keys.get(id) {
            return Ok(key.clone());
        }
        
        // Load from disk
        let key_path = self.key_path(id);
        if !key_path.exists() {
            return Err(crate::Error::storage(format!("key file not found: {:?}", id)));
        }
        
        let data = fs::read(&key_path)?;
        self.deserialize_key(&data)
    }
    
    fn delete(&mut self, id: &KeyId) -> Result<()> {
        let key_path = self.key_path(id);
        
        // Remove from disk
        if key_path.exists() {
            fs::remove_file(&key_path)?;
        }
        
        // Remove from cache
        self.keys.remove(id)
            .ok_or_else(|| crate::Error::storage(format!("key not found: {:?}", id)))?;
        
        Ok(())
    }
    
    fn list(&self) -> Result<Vec<KeyId>> {
        Ok(self.keys.keys().cloned().collect())
    }
    
    fn update_metadata(&mut self, id: &KeyId, metadata: KeyMetadata) -> Result<()> {
        if let Some(versioned_key) = self.keys.get_mut(id) {
            versioned_key.metadata = metadata;
            // Re-persist to disk
            let key_copy = versioned_key.clone();
            self.store(key_copy)?;
            Ok(())
        } else {
            Err(crate::Error::storage(format!("key not found: {:?}", id)))
        }
    }
    
    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        Ok(self.keys
            .iter()
            .filter(|(_, key)| key.metadata.state == state)
            .map(|(id, _)| id.clone())
            .collect())
    }
}

impl PersistentStorage for FileStore {
    fn flush(&mut self) -> Result<()> {
        // Re-persist all keys to ensure consistency
        let keys: Vec<_> = self.keys.values().cloned().collect();
        for key in keys {
            self.store(key)?;
        }
        Ok(())
    }

    fn load(&mut self) -> Result<()> {
        self.keys.clear();

        // Read all .json files in that directory
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let data = fs::read(&path)?;
                match self.deserialize_key(&data) {
                    Ok(key) => {
                        self.keys.insert(key.metadata.id.clone(), key);
                    }
                    Err(e) => {
                        eprintln!("WARNING: Failed to load key from {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(())
    }

    fn location(&self) -> &str {
        self.path.to_str().unwrap_or("<invalid_path>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert!(!config.encrypted);
        assert!(!config.compressed);
    }

    #[test]
    fn test_memory_store_basic_operations() {
        use crate::{Algorithm, key::SecretKey};
        use std::time::SystemTime;

        let mut store = MemoryStore::new();

        // Create a test key
        let key_id = KeyId::from_bytes([1; 16]);
        let secret_key = SecretKey::from_bytes(vec![0u8; 32], Algorithm::ChaCha20Poly1305).unwrap();
        let metadata = KeyMetadata {
            id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            state: KeyState::Active,
            version: 1,
            expires_at: None,
        };
        let versioned_key = VersionedKey {
            key: secret_key,
            metadata: metadata.clone(),
        };

        // Test store and retrieve
        store.store(versioned_key).unwrap();
        let retrieved = store.retrieve(&key_id).unwrap();
        assert_eq!(retrieved.metadata.id, key_id);
        assert_eq!(retrieved.metadata.state, KeyState::Active);

        // Test list
        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&key_id));

        // Test find by state
        let active_keys = store.find_by_state(KeyState::Active).unwrap();
        assert_eq!(active_keys.len(), 1);

        // Test delete
        store.delete(&key_id).unwrap();
        let keys = store.list().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_file_store_basic_operations() {
        use tempfile::tempdir;
        use crate::{Algorithm, key::SecretKey};
        use std::time::SystemTime;
        
        // Create temporary directory
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();
        
        // Create test key
        let key_id = KeyId::from_bytes([2; 16]);
        let secret_key = SecretKey::from_bytes(vec![0x42; 32], Algorithm::ChaCha20Poly1305).unwrap();
        let metadata = KeyMetadata {
            id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        let versioned_key = VersionedKey {
            key: secret_key,
            metadata: metadata.clone(),
        };
        
        // Test store and retrieve
        store.store(versioned_key).unwrap();
        let retrieved = store.retrieve(&key_id).unwrap();
        assert_eq!(retrieved.metadata.id, key_id);
        
        // Test persistence (create new store instance)
        let store2 = FileStore::new(temp_dir.path(), StorageConfig::default()).unwrap();
        let retrieved2 = store2.retrieve(&key_id).unwrap();
        assert_eq!(retrieved2.metadata.id, key_id);
    }
}