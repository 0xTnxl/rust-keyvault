//! Storage backend traits and implementations

use crate::{crypto::{RuntimeAead, AEAD, RandomNonceGenerator, NonceGenerator}, key::VersionedKey, KeyId, KeyMetadata, KeyState, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Deserialize, Serialize};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::SystemTime;
use argon2::Argon2;
use argon2::{Algorithm as Argon2Algorithm, Version, Params};

const KEYVAULT_SALT: &[u8] = b"rust-keyvault-argon2-salt-v1-fixed-32b";

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

    /// Rotate a key to a new version
    fn rotate_key(&mut self, id: &KeyId) -> Result<VersionedKey>;

    /// Get all verions of a key (sorted by version number)
    fn get_key_versions(&self, id: &KeyId) -> Result<Vec<VersionedKey>>;

    /// Get the latest active version of a key
    fn get_latest_key(&self, id: &KeyId) -> Result<VersionedKey>;
}

/// Extended trait for advanced key lifecycle management
/// 
/// Provides methods for managing key states and cleanup policies
/// This exxtends `KeyStore` with operations for key deprecation and revocation
pub trait KeyLifeCycle: KeyStore {
    /// Mark a particular key as deprecated (key should be able to decrypt but not encrypt)
    fn deprecate_key(&mut self, id: &KeyId) -> Result<()>;

    /// Revoke a key (key should not be used for any operations)
    fn revoke_key(&mut self, id: &KeyId) -> Result<()>;

    /// Clean up old versions based on policy
    fn cleanup_old_versions(&mut self, id: &KeyId, keep_versions: usize) -> Result<Vec<KeyId>>;
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
/// 
/// Contains key metadata and the encrypted key material for disk storage
/// The actual secret ket bytes are encrypted when `StorageConfig.encrypted` is true
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedKey {
    /// Key metadata
    metadata: KeyMetadata,
    /// Encrypted key material (as bytes)
    encrypted_key: Vec<u8>,
}

/// Trait for encrypted storage backends
/// 
/// Provides password-based intialisation and re-keying capabilites
/// for storage backends that support encryption at rest
pub trait EncryptedStore: KeyStore {
    /// Initiate the store with a master key
    fn init_with_password(&mut self, password: &[u8]) -> Result<()>; 

    /// Re-encrypt all keys with a new master key
    fn rekey(&mut self, new_password: &[u8]) -> Result<()>;

    /// Check if the store is unlocked
    fn is_unlocked(&self) -> bool;
}

/// In-memory key store
/// 
/// Thread-safe storage backend for testing and high performamce scenerios
/// where persistence is not required, please remember that all keys are lost when dropped
pub struct MemoryStore {
    keys: Arc<RwLock<HashMap<KeyId, VersionedKey>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate new key material for the given algorithm
    fn generate_new_key_material(algorithm: crate::Algorithm) -> Result<crate::key::SecretKey> {
        use crate::crypto::{SimpleSymmetricKeyGenerator, KeyGenerator};
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
            .ok_or_else(|| crate::Error::storage(format!("key not found: {id:?}")))
    }

    fn delete(&mut self, id: &KeyId) -> Result<()> {
        let mut keys = self.keys.write().map_err(|_| crate::Error::storage("lock poisoned"))?;
        keys.remove(id)
            .ok_or_else(|| crate::Error::storage(format!("key not found: {id:?}")))?;
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
            Err(crate::Error::storage(format!("key not found: {id:?}")))
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

    fn rotate_key(&mut self, id: &KeyId) -> Result<VersionedKey> {
        let current_key = self.get_latest_key(id)?;
        let mut depracated_metadata = current_key.metadata.clone();
        depracated_metadata.state = KeyState::Deprecated;
        self.update_metadata(id, depracated_metadata)?;

        let new_version = current_key.metadata.version + 1;
        let new_key_id = KeyId::generate_versioned(id, new_version)?;

        let new_secret_key = Self::generate_new_key_material(current_key.metadata.algorithm)?;
        let new_metadata = KeyMetadata {
            id: new_key_id.clone(),
            base_id: current_key.metadata.base_id.clone(),
            algorithm: current_key.metadata.algorithm,
            created_at: SystemTime::now(),
            expires_at: current_key.metadata.expires_at,
            state: KeyState::Active,
            version: new_version,
        };

        let new_versioned_key = VersionedKey {
            key: new_secret_key,
            metadata: new_metadata,
        };

        // Store the new key
        self.store(new_versioned_key.clone())?;

        Ok(new_versioned_key)
    }

    fn get_key_versions(&self, id: &KeyId) -> Result<Vec<VersionedKey>> {
        let keys = self.keys.read().map_err(|_| crate::Error::storage("lock poisoned"))?;

        let mut versions = Vec::new();

        // Look for all te keys with the same base ID but different versions
        for (_store_id, key) in keys.iter() {
            if &key.metadata.base_id == id {
                versions.push(key.clone());
            }
        }

        // Sort the IDs by version number
        versions.sort_by_key(|k| k.metadata.version);

        if versions.is_empty() {
            return Err(crate::Error::storage(format!("no versions found for this key: {id:?}")))
        }
        Ok(versions)
    }

    fn get_latest_key(&self, id: &KeyId) -> Result<VersionedKey> {
        let versions = self.get_key_versions(id)?;
        
        // Find the latest active or rotating key
        versions
            .into_iter()
            .filter(|k| matches!(k.metadata.state, KeyState::Active | KeyState::Rotating))
            .max_by_key(|k| k.metadata.version)
            .ok_or_else(|| crate::Error::storage(format!("no active key found for: {id:?}")))
    }
}

/// Configuration for file-based storage
/// 
/// Controls encryption, compression and caching behaviour for persistent storage.
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
/// 
/// Provides persistent storage of cryptographic keys with optional encryption at rest
/// The key are cached in memory for performamce and automatically loaded from disk
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
    /// 
    /// Returns the filesystem path where the key's own encrypted data is stored
    fn key_path(&self, id: &KeyId) -> PathBuf {
        let filename = format!("{id:?}.json");
        self.path.join(filename)
    }

    /// Serialize the key and optionally encrypt a key
    fn serialize_key(&self, key: &VersionedKey) -> Result<Vec<u8>> {
        let key_bytes = key.key.expose_secret().to_vec();

        let encrypted_key = if self.config.encrypted {
            if let Some(master_key) = &self.master_key {
                let aead = RuntimeAead;
                let mut nonce_gen = RandomNonceGenerator::new(
                    ChaCha20Rng::from_entropy(),
                    RuntimeAead::NONCE_SIZE
                );

                let key_id_bytes = format!("{:?}", key.metadata.id);
                let nonce = nonce_gen.generate_nonce(key_id_bytes.as_bytes())?;
                let encrypted_bytes = aead.encrypt(
                    master_key, 
                    &nonce, 
                    &key_bytes, 
                    b"rust-keyvault-key-encryption",
                )?;

                let mut result = nonce;
                result.extend_from_slice(&encrypted_bytes);
                result
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
            .map_err(|e| crate::Error::storage(format!("serilization failed: {e}"))) 
    }

    /// Deserialize and optionally decrypt a key
    fn deserialize_key(&self, data: &[u8]) -> Result<VersionedKey> {
        let persisted: PersistedKey = serde_json::from_slice(data)
            .map_err(|e| crate::Error::storage(format!("deserialization failed: {e}")))?;
        
        let key_bytes = if self.config.encrypted {
            if let Some(master_key) = &self.master_key {
                let aead = RuntimeAead;
                
                if persisted.encrypted_key.len() < RuntimeAead::NONCE_SIZE {
                    return Err(crate::Error::storage("encrypted key too short - corrupted data"));
                }
                
                let (nonce, ciphertext) = persisted.encrypted_key.split_at(RuntimeAead::NONCE_SIZE);
                
                aead.decrypt(
                    master_key,
                    nonce,
                    ciphertext,
                    b"rust-keyvault-key-encryption" 
                )?
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
    
    /// Initialize with password-derived master key (now using Argon2)
    pub fn init_with_password(&mut self, password: &[u8]) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage("encryption not enabled in config"));
        }
        
        let salt = KEYVAULT_SALT;
        let master_key = Self::derive_master_key(password, salt)?;
        self.set_master_key(master_key)?;
        
        Ok(())
    }

    /// Derive a master key from a password using Argon2id
    pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<crate::key::SecretKey> {
        let params = Params::new(
            19456, 
            2,
            1,
            Some(32),
        ).map_err(|e| crate::Error::crypto(format!("invalid Argon2 params: {e}")))?;
        
        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];
        argon2.hash_password_into(password, salt, &mut key_bytes)
            .map_err(|e| crate::Error::crypto(format!("Argon2 derivation failed: {e}")))?;

        crate::key::SecretKey::from_bytes(key_bytes.to_vec(), crate::Algorithm::ChaCha20Poly1305)
    }

    /// Generate new key material for the given algorithm
    fn generate_new_key_material(&self, algorithm: crate::Algorithm) -> Result<crate::key::SecretKey> {
        use crate::crypto::{SimpleSymmetricKeyGenerator, KeyGenerator};
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
}

impl EncryptedStore for FileStore {
    /// Initialise with password-derived master key
    fn init_with_password(&mut self, password: &[u8]) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage("encryption not enabled in config"));
        }

        let salt = KEYVAULT_SALT;
        let master_key = Self::derive_master_key(password, salt)?;
        self.set_master_key(master_key)?;

        Ok(())
    }

    fn rekey(&mut self, new_password: &[u8]) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage("encryption not enabled in config"));
        }

        // Ensure we have a current master key
        if self.master_key.is_none() {
            return Err(crate::Error::storage("store is locked - cannot rekey"));
        }

        // Collect all keys that need re-encryption
        let all_keys: Vec<_> = self.keys.values().cloned().collect();
        
        // Derive new master key
        let salt = KEYVAULT_SALT;
        let new_master_key = Self::derive_master_key(new_password, salt)?;
        
        // Set the new master key
        self.master_key = Some(new_master_key);
        
        // Re-encrypt all keys with the new master key
        for key in all_keys {
            self.store(key)?;
        }
        
        Ok(())
    }

    /// Check if the store is unlocked (has a master key available)
    /// 
    /// Returns `true` if a master key has been set and the store can decrypt keys
    fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
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
            return Err(crate::Error::storage(format!("key file not found: {id:?}")));
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
            .ok_or_else(|| crate::Error::storage(format!("key not found: {id:?}")))?;
        
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
            Err(crate::Error::storage(format!("key not found: {id:?}")))
        }
    }
    
    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        Ok(self.keys
            .iter()
            .filter(|(_, key)| key.metadata.state == state)
            .map(|(id, _)| id.clone())
            .collect())
    }

    fn rotate_key(&mut self, id: &KeyId) -> Result<VersionedKey> {
        let current_key = self.get_latest_key(id)?;
        
        let mut deprecated_metadata = current_key.metadata.clone();
        deprecated_metadata.state = KeyState::Deprecated;
        self.update_metadata(id, deprecated_metadata)?;
        
        let new_version = current_key.metadata.version + 1;
        let new_key_id = KeyId::generate_versioned(id, new_version)?;

        let new_secret_key = self.generate_new_key_material(current_key.key.algorithm())?;
        let new_metadata = KeyMetadata {
            id: new_key_id.clone(),
            algorithm: current_key.metadata.algorithm,
            created_at: SystemTime::now(),
            expires_at: current_key.metadata.expires_at,
            state: KeyState::Active,
            version: new_version,
            base_id: current_key.metadata.base_id.clone(),
        };
        
        let new_versioned_key = VersionedKey {
            key: new_secret_key,
            metadata: new_metadata,
        };
        
        // 5. Store the new key
        self.store(new_versioned_key.clone())?;
        
        Ok(new_versioned_key)
    }

    fn get_key_versions(&self, id: &KeyId) -> Result<Vec<VersionedKey>> {
        let mut versions = Vec::new();
        
        // Look for all keys with the same base ID but different versions
        for key in self.keys.values() {
            if &key.metadata.base_id == id {
                versions.push(key.clone());
            }
        }
        
        // Sort by version number
        versions.sort_by_key(|k| k.metadata.version);
        
        if versions.is_empty() {
            return Err(crate::Error::storage(format!("no versions found for key: {id:?}")));
        }
        
        Ok(versions)
    }

    fn get_latest_key(&self, id: &KeyId) -> Result<VersionedKey> {
        let versions = self.get_key_versions(id)?;
        
        // Find the latest active or rotating key
        versions
            .into_iter()
            .filter(|k| matches!(k.metadata.state, KeyState::Active | KeyState::Rotating))
            .max_by_key(|k| k.metadata.version)
            .ok_or_else(|| crate::Error::storage(format!("no active key found for: {id:?}")))
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
                        eprintln!("WARNING: Failed to load key from {path:?}: {e}");
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

impl KeyLifeCycle for FileStore {
    fn deprecate_key(&mut self, id: &KeyId) -> Result<()> {
        let key = self.retrieve(id)?;
        
        if !matches!(key.metadata.state, KeyState::Active | KeyState::Rotating) {
            return Err(crate::Error::InvalidKeyState(
                format!("cannot deprecate key in state: {:?}", key.metadata.state)
            ));
        }
        
        let mut new_metadata = key.metadata.clone();
        new_metadata.state = KeyState::Deprecated;
        
        self.update_metadata(id, new_metadata)
    }
    
    fn revoke_key(&mut self, id: &KeyId) -> Result<()> {
        let key = self.retrieve(id)?;
        
        let mut new_metadata = key.metadata.clone();
        new_metadata.state = KeyState::Revoked;
        
        self.update_metadata(id, new_metadata)
    }
    
    fn cleanup_old_versions(&mut self, id: &KeyId, keep_versions: usize) -> Result<Vec<KeyId>> {
        let mut versions = self.get_key_versions(id)?;
        
        // Sort by version (newest first)
        versions.sort_by_key(|k| std::cmp::Reverse(k.metadata.version));
        
        let mut removed_keys = Vec::new();
        
        // Keep the specified number of versions, remove the rest
        for key_to_remove in versions.iter().skip(keep_versions) {
            if matches!(key_to_remove.metadata.state, KeyState::Revoked | KeyState::Deprecated) {
                self.delete(&key_to_remove.metadata.id)?;
                removed_keys.push(key_to_remove.metadata.id.clone());
            }
        }
        
        Ok(removed_keys)
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
            base_id: key_id.clone(),
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
            base_id: key_id.clone(),
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

    #[test]
    fn test_file_store_encryption() {
        use tempfile::tempdir;
        use crate::{Algorithm, key::SecretKey};
        use std::time::SystemTime;
        
        // Create encrypted store
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();
        
        // Initialize with password and verify unlock state
        store.init_with_password(b"super-secret-password-123").unwrap();
        assert!(store.is_unlocked());
        
        // Create and store a key
        let key_id = KeyId::from_bytes([3; 16]);
        let secret_key = SecretKey::from_bytes(vec![0xFF; 32], Algorithm::ChaCha20Poly1305).unwrap();
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        let versioned_key = VersionedKey { key: secret_key, metadata };
        
        // Store and retrieve - verify round-trip works
        store.store(versioned_key.clone()).unwrap();
        let retrieved = store.retrieve(&key_id).unwrap();
        
        // Verify the key material and metadata match
        assert_eq!(retrieved.key.expose_secret(), versioned_key.key.expose_secret());
        assert_eq!(retrieved.metadata.id, key_id);
        assert_eq!(retrieved.metadata.algorithm, Algorithm::ChaCha20Poly1305);
        
        // Verify file is actually encrypted (contains no plaintext key material)
        let key_file = store.key_path(&key_id);
        let file_contents = std::fs::read_to_string(key_file).unwrap();
        
        // The file should NOT contain the raw key bytes in any common format
        assert!(!file_contents.contains("FFFFFFFF"));    // Hex representation
        assert!(!file_contents.contains("/////"));       // Base64 for 0xFF repeated
        assert!(!file_contents.contains("255"));         // JSON number representation
        
        // But it should contain the expected structure
        assert!(file_contents.contains("ChaCha20Poly1305")); // Algorithm in metadata
        assert!(file_contents.contains("encrypted_key"));     // Field name
        
        // Verify the encrypted_key field contains binary data (not readable text)
        let parsed: serde_json::Value = serde_json::from_str(&file_contents).unwrap();
        let encrypted_array = parsed["encrypted_key"].as_array().unwrap();
        assert!(encrypted_array.len() > 32); // Should be nonce(12) + ciphertext(32) + tag(16) = 60 bytes minimum
    }

    #[test]
    fn test_file_store_wrong_password_fails() {
        use tempfile::tempdir;
        use crate::{Algorithm, key::SecretKey};
        use std::time::SystemTime;
        
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig { encrypted: true, ..Default::default() };
        
        // Create and populate store with correct password
        let mut store1 = FileStore::new(temp_dir.path(), config.clone()).unwrap();
        store1.init_with_password(b"correct-password").unwrap();
        
        let key_id = KeyId::from_bytes([4; 16]);
        let secret_key = SecretKey::from_bytes(vec![0xAB; 32], Algorithm::Aes256Gcm).unwrap();
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::Aes256Gcm,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        let versioned_key = VersionedKey { key: secret_key, metadata };
        
        store1.store(versioned_key).unwrap();
        
        // Try to read with wrong password - should fail
        let mut store2 = FileStore::new(temp_dir.path(), config).unwrap();
        store2.init_with_password(b"wrong-password").unwrap();
        
        // This should fail because decryption will fail with wrong master key
        let result = store2.retrieve(&key_id);
        assert!(result.is_err());
        
        // The error should be a crypto error (AEAD decryption failure)
        match result.unwrap_err() {
            crate::Error::CryptoError(_) => {}, // Expected
            other => panic!("Expected crypto error, got: {:?}", other),
        }
    }

    #[test]
    fn test_file_store_persistence_across_restarts() {
        use tempfile::tempdir;
        use crate::{Algorithm, key::SecretKey};
        use std::time::SystemTime;
        
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig { encrypted: true, ..Default::default() };
        let password = b"persistent-test-password";
        
        let key_id = KeyId::from_bytes([5; 16]);
        let original_key_bytes = vec![0x12; 32]; // 32 bytes for ChaCha20Poly1305
        
        // First session: create and store key
        {
            let mut store = FileStore::new(temp_dir.path(), config.clone()).unwrap();
            store.init_with_password(password).unwrap();
            
            let secret_key = SecretKey::from_bytes(original_key_bytes.clone(), Algorithm::ChaCha20Poly1305).unwrap();
            let metadata = KeyMetadata {
                id: key_id.clone(),
                base_id: key_id.clone(),
                algorithm: Algorithm::ChaCha20Poly1305,
                created_at: SystemTime::now(),
                expires_at: None,
                state: KeyState::Active,
                version: 1,
            };
            let versioned_key = VersionedKey { key: secret_key, metadata };
            
            store.store(versioned_key).unwrap();
        } // store goes out of scope, simulating restart
        
        // Second session: load and verify key
        {
            let mut store = FileStore::new(temp_dir.path(), config).unwrap();
            store.init_with_password(password).unwrap();
            
            let retrieved = store.retrieve(&key_id).unwrap();
            assert_eq!(retrieved.key.expose_secret(), &original_key_bytes);
            assert_eq!(retrieved.metadata.algorithm, Algorithm::ChaCha20Poly1305);
        }
    }
}