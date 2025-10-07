//! Storage backend traits and implementations

use crate::audit::{AuditEvent, AuditLogEntry, AuditLogger, NoOpLogger};
use crate::{
    crypto::{NonceGenerator, RandomNonceGenerator, RuntimeAead, AEAD},
    key::VersionedKey,
    KeyId, KeyMetadata, KeyState, Result,
};
use argon2::Argon2;
use argon2::{Algorithm as Argon2Algorithm, Params, Version};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Salt storage for master key derivation
#[derive(Clone, Serialize, Deserialize)]
struct VaultMetadata {
    /// Unique Salt for this vault instance
    salt: Vec<u8>,
    /// Vault creation timestamp
    created_at: SystemTime,
    /// Version of the vault format
    format_version: u32,
}

impl std::fmt::Debug for VaultMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultMetadata")
            .field("salt", &format!("[REDACTED {} bytes]", self.salt.len()))
            .field("created_at", &self.created_at)
            .field("format_version", &self.format_version)
            .finish()
    }
}

impl VaultMetadata {
    /// Create new metadata with random salt
    fn new() -> Result<Self> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);

        Ok(Self {
            salt,
            created_at: SystemTime::now(),
            format_version: 1,
        })
    }
}

///
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Memory cost in KiB (default: 19456 = ~19 MiB)
    pub memory_kib: u32,
    /// Time cost (iterations, default: 3)
    pub time_cost: u32,
    /// Parallelism (threads, default: 4)
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_kib: 19456, // 19 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

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
#[derive(Clone, Serialize, Deserialize)]
struct PersistedKey {
    /// Key metadata
    metadata: KeyMetadata,
    /// Encrypted key material (as bytes)
    encrypted_key: Vec<u8>,
}

impl std::fmt::Debug for PersistedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedKey")
            .field("metadata", &self.metadata)
            .field(
                "encrypted_key",
                &format!("[REDACTED {} bytes]", self.encrypted_key.len()),
            )
            .finish()
    }
}

/// In-memory key store
///
/// Thread-safe storage backend for testing and high performance scenerios
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
}

impl KeyStore for MemoryStore {
    fn store(&mut self, key: VersionedKey) -> Result<()> {
        let key_id = key.metadata.id.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        keys.insert(key_id, key);
        Ok(())
    }

    fn retrieve(&self, id: &KeyId) -> Result<VersionedKey> {
        let keys = self
            .keys
            .read()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        keys.get(id)
            .cloned()
            .ok_or_else(|| crate::Error::storage("retrieve", &format!("key not found: {id:?}")))
    }

    fn delete(&mut self, id: &KeyId) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        keys.remove(id)
            .ok_or_else(|| crate::Error::storage("delete", &format!("key not found: {id:?}")))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyId>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        Ok(keys.keys().cloned().collect())
    }

    fn update_metadata(&mut self, id: &KeyId, metadata: KeyMetadata) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        if let Some(versioned_key) = keys.get_mut(id) {
            versioned_key.metadata = metadata;
            Ok(())
        } else {
            Err(crate::Error::storage(
                "update_metadata",
                &format!("key not found: {id:?}"),
            ))
        }
    }

    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;
        Ok(keys
            .iter()
            .filter(|(_, versioned_key)| versioned_key.metadata.state == state)
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
        let keys = self
            .keys
            .read()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;

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
            return Err(crate::Error::storage(
                "get_key_versions",
                &format!("no versions found for key: {id:?}"),
            ));
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
            .ok_or_else(|| {
                crate::Error::storage(
                    "get_latest_key",
                    &format!("no active key found for: {id:?}"),
                )
            })
    }
}

impl KeyLifeCycle for MemoryStore {
    fn deprecate_key(&mut self, id: &KeyId) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;

        if let Some(key) = keys.get_mut(id) {
            if !matches!(key.metadata.state, KeyState::Active | KeyState::Rotating) {
                return Err(crate::Error::InvalidKeyState {
                    key_id: format!("{:?}", id),
                    state: format!("{:?}", key.metadata.state),
                    operation: "deprecate_key".to_string(),
                });
            }

            key.metadata.state = KeyState::Deprecated;
            Ok(())
        } else {
            Err(crate::Error::storage(
                "deprecate_key",
                &format!("key not found: {id:?}"),
            ))
        }
    }

    fn revoke_key(&mut self, id: &KeyId) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| crate::Error::storage("lock_acquire", "lock poisoned"))?;

        if let Some(key) = keys.get_mut(id) {
            key.metadata.state = KeyState::Revoked;
            Ok(())
        } else {
            Err(crate::Error::storage(
                "revoke_key",
                &format!("key not found: {id:?}"),
            ))
        }
    }

    fn cleanup_old_versions(&mut self, id: &KeyId, keep_versions: usize) -> Result<Vec<KeyId>> {
        let mut versions = self.get_key_versions(id)?;

        versions.sort_by_key(|k| std::cmp::Reverse(k.metadata.version));

        let mut removed_keys = Vec::new();

        for key_to_remove in versions.iter().skip(keep_versions) {
            if matches!(
                key_to_remove.metadata.state,
                KeyState::Revoked | KeyState::Deprecated
            ) {
                self.delete(&key_to_remove.metadata.id)?;
                removed_keys.push(key_to_remove.metadata.id.clone());
            }
        }

        Ok(removed_keys)
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
    /// Enable compression
    pub compressed: bool,
    /// Maximum number of keys to cache in memory
    pub cache_size: usize,
    ///
    pub argon2_config: Argon2Config,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: None,
            encrypted: false,
            compressed: false,
            cache_size: 100,
            argon2_config: Argon2Config::default(),
        }
    }
}

impl StorageConfig {
    /// Create a config with high security Argon2 parameters
    pub fn high_security() -> Self {
        Self {
            encrypted: true,
            argon2_config: Argon2Config {
                memory_kib: 65536,
                time_cost: 4,
                parallelism: 4,
            },
            ..Default::default()
        }
    }

    ///
    pub fn balanced() -> Self {
        Self {
            encrypted: true,
            argon2_config: Argon2Config::default(), // 19 MiB, t=3, p=4
            ..Default::default()
        }
    }

    ///
    pub fn fast_insecure() -> Self {
        Self {
            encrypted: true,
            argon2_config: Argon2Config {
                memory_kib: 8192, // 8 MiB - INSECURE, testing only!
                time_cost: 1,
                parallelism: 1,
            },
            ..Default::default()
        }
    }
}

/// File-based key store with optional encryption
///
/// Provides persistent storage of cryptographic keys with optional encryption at rest
/// The key are cached in memory for performance and automatically loaded from disk
pub struct FileStore {
    /// Directory path for key storage
    path: PathBuf,
    /// In-memory cache of loaded keys
    keys: HashMap<KeyId, VersionedKey>,
    /// Configuration
    config: StorageConfig,
    /// Master key for encryption (optional, i.e. if enabled)
    master_key: Option<crate::key::SecretKey>,
    /// Metadata for the key vault for instance (e.g. salt)
    vault_metadata: Option<VaultMetadata>,
    /// Audit logger for security events
    audit_logger: Box<dyn AuditLogger>,
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("path", &self.path)
            .field("keys", &format!("[{} keys]", self.keys.len()))
            .field("config", &self.config)
            .field(
                "master_key",
                &if self.master_key.is_some() {
                    "[SET]"
                } else {
                    "[NOT SET]"
                },
            )
            .field("vault_metadata", &self.vault_metadata)
            .field("audit_logger", &"[...]")
            .finish()
    }
}

impl FileStore {
    /// Create a new FileStore at the given path
    pub fn new<P: AsRef<Path>>(path: P, config: StorageConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            fs::create_dir_all(&path)?;
        }

        let mut store = Self {
            path,
            keys: HashMap::new(),
            config,
            master_key: None,
            vault_metadata: None,
            audit_logger: Box::new(NoOpLogger), // should default to no-op
        };

        // Load or create vault metadata FIRST
        store.load_metadata()?; // ← Add this line

        // Then load keys
        store.load()?;

        Ok(store)
    }

    ///
    pub fn rekey(&mut self, new_password: &[u8]) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage(
                "rekey",
                "encryption not enabled in config",
            ));
        }

        // Ensure we have a current master key
        if self.master_key.is_none() {
            return Err(crate::Error::storage(
                "rekey",
                "store is locked - cannot rekey",
            ));
        }

        // Collect all keys that need re-encryption
        let all_keys: Vec<_> = self.keys.values().cloned().collect();

        // Get salt from vault metadata
        let salt = &self
            .vault_metadata
            .as_ref()
            .ok_or_else(|| crate::Error::storage("rekey", "vault metadata not initialized"))?
            .salt;

        // Derive new master key with the config
        let new_master_key =
            Self::derive_master_key(new_password, salt, &self.config.argon2_config)?;

        // Set the new master key
        self.master_key = Some(new_master_key);

        // Re-encrypt all keys with the new master key
        for key in all_keys {
            self.store(key)?;
        }

        Ok(())
    }

    /// Set master key for encryption
    pub fn set_master_key(&mut self, key: crate::key::SecretKey) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage(
                "set_master_key",
                "encryption not enabled in config",
            ));
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
                // Use the nonce size appropriate for the master key's algorithm
                let nonce_size = match master_key.algorithm() {
                    crate::Algorithm::XChaCha20Poly1305 => 24,
                    _ => 12, // ChaCha20Poly1305 and AES-256-GCM both use 12
                };
                let mut nonce_gen =
                    RandomNonceGenerator::new(ChaCha20Rng::from_entropy(), nonce_size);

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
                return Err(crate::Error::storage(
                    "serialize_key",
                    "encryption enabled but no master key set",
                ));
            }
        } else {
            key_bytes
        };

        let persisted = PersistedKey {
            metadata: key.metadata.clone(),
            encrypted_key,
        };

        serde_json::to_vec(&persisted).map_err(|e| {
            crate::Error::storage("serialize_key", &format!("serialization failed: {e}"))
        })
    }

    /// Deserialize and optionally decrypt a key
    fn deserialize_key(&self, data: &[u8]) -> Result<VersionedKey> {
        let persisted: PersistedKey = serde_json::from_slice(data).map_err(|e| {
            crate::Error::storage("deserialize_key", &format!("deserialization failed: {e}"))
        })?;

        let key_bytes = if self.config.encrypted {
            if let Some(master_key) = &self.master_key {
                let aead = RuntimeAead;

                // Determine nonce size based on master key algorithm
                let nonce_size = match master_key.algorithm() {
                    crate::Algorithm::XChaCha20Poly1305 => 24,
                    _ => 12, // ChaCha20Poly1305 and AES-256-GCM both use 12
                };

                if persisted.encrypted_key.len() < nonce_size {
                    return Err(crate::Error::storage(
                        "deserialize_key",
                        "encrypted key too short - corrupted data",
                    ));
                }

                let (nonce, ciphertext) = persisted.encrypted_key.split_at(nonce_size);

                aead.decrypt(
                    master_key,
                    nonce,
                    ciphertext,
                    b"rust-keyvault-key-encryption",
                )?
            } else {
                return Err(crate::Error::storage(
                    "deserialize_key",
                    "encrypted key but no master key available",
                ));
            }
        } else {
            persisted.encrypted_key
        };

        let secret_key =
            crate::key::SecretKey::from_bytes(key_bytes, persisted.metadata.algorithm)?;

        Ok(VersionedKey {
            key: secret_key,
            metadata: persisted.metadata,
        })
    }

    /// Initialize with password-derived master key (now using per-vault salt)
    pub fn init_with_password(&mut self, password: &[u8]) -> Result<()> {
        if !self.config.encrypted {
            return Err(crate::Error::storage(
                "init_with_password",
                "encryption not enabled in config",
            ));
        }

        let salt = &self
            .vault_metadata
            .as_ref()
            .ok_or_else(|| {
                crate::Error::storage("init_with_password", "vault metadata not initialized")
            })?
            .salt;

        let result = Self::derive_master_key(password, salt, &self.config.argon2_config);

        // Audit log authentication attempt
        let success = result.is_ok();
        let event = AuditEvent::AuthenticationAttempt {
            success,
            storage_path: self.path.to_string_lossy().to_string(),
        };
        self.audit_logger.log(AuditLogEntry::new(event))?;

        let master_key = result?;
        self.set_master_key(master_key)?;

        Ok(())
    }

    /// Derive a master key from a password using Argon2id
    pub fn derive_master_key(
        password: &[u8],
        salt: &[u8],
        argon2_config: &Argon2Config,
    ) -> Result<crate::key::SecretKey> {
        let params = Params::new(
            argon2_config.memory_kib,
            argon2_config.time_cost,
            argon2_config.parallelism,
            Some(32), // output length: 32 bytes
        )
        .map_err(|e| {
            crate::Error::crypto("argon2_config", &format!("invalid Argon2 params: {}", e))
        })?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password, salt, &mut key_bytes)
            .map_err(|e| {
                crate::Error::crypto("argon2_hash", &format!("Argon2 derivation failed: {}", e))
            })?;

        crate::key::SecretKey::from_bytes(key_bytes.to_vec(), crate::Algorithm::ChaCha20Poly1305)
    }

    /// Generate new key material for the given algorithm
    fn generate_new_key_material(
        &self,
        algorithm: crate::Algorithm,
    ) -> Result<crate::key::SecretKey> {
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

    fn metadata_path(&self) -> PathBuf {
        self.path.join(".vault_metadata.json")
    }

    fn load_metadata(&mut self) -> Result<()> {
        let metadata_path = self.metadata_path();

        if metadata_path.exists() {
            let data = fs::read(&metadata_path)?;
            let metadata: VaultMetadata = serde_json::from_slice(&data).map_err(|e| {
                crate::Error::storage(
                    "load_vault_metadata",
                    &format!("failed to parse vault metadata: {}", e),
                )
            })?;
            self.vault_metadata = Some(metadata);
        } else {
            let metadata = VaultMetadata::new()?;
            let data = serde_json::to_vec_pretty(&metadata).map_err(|e| {
                crate::Error::storage(
                    "load_vault_metadata",
                    &format!("failed to serialize vault metadata: {}", e),
                )
            })?;
            fs::write(&metadata_path, data)?;
            self.vault_metadata = Some(metadata);
        }

        Ok(())
    }

    /// Enable audit logging to a file
    pub fn enable_audit_log<P: AsRef<Path>>(&mut self, log_path: P) -> Result<()> {
        use crate::audit::FileAuditLogger;
        self.audit_logger = Box::new(FileAuditLogger::new(log_path)?);
        Ok(())
    }

    /// Set a custom audit logger
    pub fn set_audit_logger(&mut self, logger: Box<dyn AuditLogger>) {
        self.audit_logger = logger;
    }

    /// Export a key to a secure, portable format
    ///
    /// The key is encrypted with a password-derived key using Argon2id.
    /// The exported key includes all metadata and can be imported into another vault.
    pub fn export_key(
        &mut self,
        id: &KeyId,
        password: &[u8],
    ) -> Result<crate::export::ExportedKey> {
        use crate::export::ExportedKey;

        // Retrieve the key
        let versioned_key = self.retrieve(id)?;

        // Use XChaCha20Poly1305 for export (supports larger nonces for safety)
        let exported = ExportedKey::new(
            &versioned_key.key,
            versioned_key.metadata.clone(),
            password,
            crate::Algorithm::XChaCha20Poly1305,
        )?;

        // Audit log the export
        let event = AuditEvent::KeyAccessed {
            key_id: format!("{:?}", id),
            operation: "export".to_string(),
        };
        self.audit_logger.log(AuditLogEntry::new(event))?;

        Ok(exported)
    }

    /// Import a key from an exported format
    ///
    /// Validates the key, decrypts it with the provided password, and stores it in the vault.
    /// The key will maintain its original metadata (algorithm, version, etc.).
    pub fn import_key(
        &mut self,
        exported: &crate::export::ExportedKey,
        password: &[u8],
    ) -> Result<KeyId> {
        // Decrypt the key
        let key = exported.decrypt(password)?;

        // Verify the algorithm matches metadata
        if key.algorithm() != exported.metadata.algorithm {
            return Err(crate::Error::SerializationError {
                operation: "import_key".to_string(),
                message: "key algorithm mismatch with metadata".to_string(),
            });
        }

        // Create versioned key
        let versioned_key = VersionedKey {
            key,
            metadata: exported.metadata.clone(),
        };

        let key_id = versioned_key.metadata.id.clone();

        // Store the key
        self.store(versioned_key)?;

        // Audit log the import
        let event = AuditEvent::KeyAccessed {
            key_id: format!("{:?}", key_id),
            operation: "import".to_string(),
        };
        self.audit_logger.log(AuditLogEntry::new(event))?;

        Ok(key_id)
    }

    /// Create a full backup of the vault
    ///
    /// # Arguments
    /// * `password` - Password to encrypt the backup
    /// * `config` - Backup configuration
    ///
    /// # Returns
    /// The encrypted backup that can be saved to a file
    ///
    /// # Security
    /// The backup is encrypted using Argon2id key derivation and XChaCha20Poly1305 AEAD.
    /// All key material is protected with high-security parameters.
    pub fn backup(
        &mut self,
        password: &[u8],
        config: crate::backup::BackupConfig,
    ) -> Result<crate::backup::VaultBackup> {
        use crate::backup::{BackupData, VaultInfo};

        // Collect all keys in the vault
        let mut exported_keys = Vec::new();

        // Get all key IDs from cache
        let key_ids: Vec<_> = self.keys.keys().cloned().collect();

        // Export each key with a temporary password
        let temp_password = b"temp-internal-export-password-for-backup";
        for key_id in key_ids {
            if let Ok(exported) = self.export_key(&key_id, temp_password) {
                exported_keys.push(exported);
            }
        }

        // Collect audit logs if requested
        let audit_logs = if config.include_audit_logs {
            // Note: We would need to add a method to get all audit entries
            // For now, we'll skip this
            None
        } else {
            None
        };

        // Get vault creation time
        let created_at = self
            .vault_metadata
            .as_ref()
            .map(|m| m.created_at)
            .unwrap_or_else(SystemTime::now);

        // Create backup data
        let backup_data = BackupData {
            keys: exported_keys,
            audit_logs,
            vault_info: VaultInfo {
                created_at,
                operation_count: 0, // Could track this in metadata
            },
        };

        // Create encrypted backup
        crate::backup::VaultBackup::new(&backup_data, password, &config)
    }

    /// Restore a vault from a backup
    ///
    /// # Arguments
    /// * `backup` - The encrypted backup to restore
    /// * `password` - Password used to encrypt the backup
    ///
    /// # Errors
    /// Returns an error if:
    /// - Password is incorrect
    /// - Backup is corrupted
    /// - Keys cannot be imported
    pub fn restore(
        &mut self,
        backup: &crate::backup::VaultBackup,
        password: &[u8],
    ) -> Result<usize> {
        // Decrypt the backup
        let backup_data = backup.decrypt(password)?;

        // Import all keys
        let temp_password = b"temp-internal-export-password-for-backup";
        let mut imported_count = 0;

        for exported_key in backup_data.keys {
            if let Ok(_) = self.import_key(&exported_key, temp_password) {
                imported_count += 1;
            }
        }

        Ok(imported_count)
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
        self.keys.insert(key_id.clone(), key.clone());

        // Audit log the operation
        let event = AuditEvent::KeyCreated {
            key_id: format!("{:?}", key_id),
            algorithm: key.metadata.algorithm,
            version: key.metadata.version,
        };
        self.audit_logger.log(AuditLogEntry::new(event))?;

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
            return Err(crate::Error::storage(
                "retrieve",
                &format!("key file not found: {id:?}"),
            ));
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

        // Remove from cachestell
        self.keys.remove(id).ok_or_else(|| {
            crate::Error::storage("remove_from_cache", &format!("key not found: {id:?}"))
        })?;

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
            Err(crate::Error::storage(
                "update_metadata",
                &format!("key not found: {id:?}"),
            ))
        }
    }

    fn find_by_state(&self, state: KeyState) -> Result<Vec<KeyId>> {
        Ok(self
            .keys
            .iter()
            .filter(|(_, key)| key.metadata.state == state)
            .map(|(id, _)| id.clone())
            .collect())
    }

    fn rotate_key(&mut self, id: &KeyId) -> Result<VersionedKey> {
        let current_key = self.get_latest_key(id)?;
        let old_version = current_key.metadata.version;

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

        self.store(new_versioned_key.clone())?;

        // Audit log rotation
        let event = AuditEvent::KeyRotated {
            base_id: format!("{:?}", id),
            old_version,
            new_version,
        };
        self.audit_logger.log(AuditLogEntry::new(event))?;

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
            return Err(crate::Error::storage(
                "sort_by_version_number",
                &format!("no versions found for key: {id:?}"),
            ));
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
            .ok_or_else(|| {
                crate::Error::storage(
                    "find_active_or_rotating_key",
                    &format!("no active key found for: {id:?}"),
                )
            })
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

        // Read all .json files in that directory (except vault metadata)
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let path = entry.path();

            // Skip the vault metadata file - it has a different format
            if path.file_name().and_then(|s| s.to_str()) == Some(".vault_metadata.json") {
                continue;
            }

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
            return Err(crate::Error::InvalidKeyState {
                key_id: format!("{:?}", id),
                state: format!("{:?}", key.metadata.state),
                operation: "deprecate_key".to_string(),
            });
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
            if matches!(
                key_to_remove.metadata.state,
                KeyState::Revoked | KeyState::Deprecated
            ) {
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
        use crate::{key::SecretKey, Algorithm};
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
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        // Create temporary directory
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();

        // Create test key
        let key_id = KeyId::from_bytes([2; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0x42; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        // Create encrypted store
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();

        // Initialize with password and verify unlock state
        store
            .init_with_password(b"super-secret-password-123")
            .unwrap();

        // Create and store a key
        let key_id = KeyId::from_bytes([3; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0xFF; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
            metadata,
        };

        // Store and retrieve - verify round-trip works
        store.store(versioned_key.clone()).unwrap();
        let retrieved = store.retrieve(&key_id).unwrap();

        // Verify the key material and metadata match
        assert_eq!(
            retrieved.key.expose_secret(),
            versioned_key.key.expose_secret()
        );
        assert_eq!(retrieved.metadata.id, key_id);
        assert_eq!(retrieved.metadata.algorithm, Algorithm::ChaCha20Poly1305);

        // Verify file is actually encrypted (contains no plaintext key material)
        let key_file = store.key_path(&key_id);
        let file_contents = std::fs::read_to_string(key_file).unwrap();

        // The file should NOT contain the raw key bytes in any common format
        assert!(!file_contents.contains("FFFFFFFF")); // Hex representation
        assert!(!file_contents.contains("/////")); // Base64 for 0xFF repeated
        assert!(!file_contents.contains("255")); // JSON number representation

        // But it should contain the expected structure
        assert!(file_contents.contains("ChaCha20Poly1305")); // Algorithm in metadata
        assert!(file_contents.contains("encrypted_key")); // Field name

        // Verify the encrypted_key field contains binary data (not readable text)
        let parsed: serde_json::Value = serde_json::from_str(&file_contents).unwrap();
        let encrypted_array = parsed["encrypted_key"].as_array().unwrap();
        assert!(encrypted_array.len() > 32); // Should be nonce(12) + ciphertext(32) + tag(16) = 60 bytes minimum
    }

    #[test]
    fn test_file_store_wrong_password_fails() {
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };

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
        let versioned_key = VersionedKey {
            key: secret_key,
            metadata,
        };

        store1.store(versioned_key).unwrap();

        // Try to read with wrong password - should fail
        let mut store2 = FileStore::new(temp_dir.path(), config).unwrap();
        store2.init_with_password(b"wrong-password").unwrap();

        // This should fail because decryption will fail with wrong master key
        let result = store2.retrieve(&key_id);
        assert!(result.is_err());

        // The error should be a crypto error (AEAD decryption failure)
        match result.unwrap_err() {
            crate::Error::CryptoError { .. } => {} // Expected
            other => panic!("Expected crypto error, got: {:?}", other),
        }
    }

    #[test]
    fn test_file_store_persistence_across_restarts() {
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };
        let password = b"persistent-test-password";

        let key_id = KeyId::from_bytes([5; 16]);
        let original_key_bytes = vec![0x12; 32]; // 32 bytes for ChaCha20Poly1305

        // First session: create and store key
        {
            let mut store = FileStore::new(temp_dir.path(), config.clone()).unwrap();
            store.init_with_password(password).unwrap();

            let secret_key =
                SecretKey::from_bytes(original_key_bytes.clone(), Algorithm::ChaCha20Poly1305)
                    .unwrap();
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
                metadata,
            };

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

    #[test]
    fn test_custom_argon2_config() {
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();

        // Use custom Argon2 config
        let config = StorageConfig {
            encrypted: true,
            argon2_config: Argon2Config {
                memory_kib: 32768, // 32 MiB
                time_cost: 4,
                parallelism: 2,
            },
            ..Default::default()
        };

        let mut store = FileStore::new(temp_dir.path(), config).unwrap();
        store.init_with_password(b"test-password").unwrap();

        let key_id = KeyId::from_bytes([10; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0x77; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
            metadata,
        };

        store.store(versioned_key).unwrap();
        let retrieved = store.retrieve(&key_id).unwrap();
        assert_eq!(retrieved.metadata.id, key_id);
    }

    #[test]
    fn test_memory_store_lifecycle() {
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;

        let mut store = MemoryStore::new();

        // Create and store a key
        let key_id = KeyId::from_bytes([20; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0x55; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
            metadata,
        };
        store.store(versioned_key).unwrap();

        // Test deprecate
        store.deprecate_key(&key_id).unwrap();
        let key = store.retrieve(&key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Deprecated);

        // Test revoke
        store.revoke_key(&key_id).unwrap();
        let key = store.retrieve(&key_id).unwrap();
        assert_eq!(key.metadata.state, KeyState::Revoked);
    }

    #[test]
    fn test_memory_store_cleanup_old_versions() {
        use crate::{key::SecretKey, Algorithm};
        use std::time::SystemTime;

        let mut store = MemoryStore::new();

        // Create base key with multiple versions
        let base_id = KeyId::generate_base().unwrap();
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let metadata = KeyMetadata {
            id: base_id.clone(),
            base_id: base_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            state: KeyState::Active,
            version: 1,
            expires_at: None,
        };
        let initial_key = VersionedKey {
            key: secret_key,
            metadata,
        };
        store.store(initial_key).unwrap();

        // Create 5 versions total
        for _ in 2..=5 {
            store.rotate_key(&base_id).unwrap();
        }

        // Deprecate old versions
        let versions = store.get_key_versions(&base_id).unwrap();
        for old_version in &versions[..3] {
            store.deprecate_key(&old_version.metadata.id).unwrap();
        }

        // Cleanup, keep only 2 most recent
        let removed = store.cleanup_old_versions(&base_id, 2).unwrap();
        assert_eq!(removed.len(), 3);

        // Verify remaining
        let remaining = store.get_key_versions(&base_id).unwrap();
        assert!(remaining.len() <= 2);
    }

    #[test]
    fn test_audit_logging() {
        use crate::{audit::MemoryAuditLogger, key::SecretKey, Algorithm};
        use std::time::SystemTime;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();

        // Set up memory logger for testing
        let logger = Box::new(MemoryAuditLogger::new());
        store.set_audit_logger(logger);

        // Create and store a key
        let key_id = KeyId::from_bytes([99; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0x88; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
            metadata,
        };

        store.store(versioned_key).unwrap();

        // Verify audit log captured the event
        // Note: To actually verify, we'd need to extract the logger back out
        // For now, this tests that auditing doesn't break functionality
    }

    #[test]
    fn test_high_security_config() {
        let config = StorageConfig::high_security();
        assert_eq!(config.argon2_config.memory_kib, 65536);
        assert_eq!(config.argon2_config.time_cost, 4);
        assert!(config.encrypted);
    }

    #[test]
    fn test_safe_debug_implementations() {
        use crate::key::SecretKey;
        use crate::Algorithm;
        use tempfile::tempdir;

        // Test VaultMetadata redacts salt
        let metadata = VaultMetadata::new().unwrap();
        let debug_output = format!("{:?}", metadata);
        assert!(debug_output.contains("VaultMetadata"));
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains(&format!("{:?}", metadata.salt)));

        // Test PersistedKey redacts encrypted_key
        let key_id = KeyId::from_bytes([42; 16]);
        let _secret_key =
            SecretKey::from_bytes(vec![0x11; 32], Algorithm::ChaCha20Poly1305).unwrap();
        let key_metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };

        let persisted = PersistedKey {
            metadata: key_metadata,
            encrypted_key: vec![0xFF; 64],
        };

        let debug_output = format!("{:?}", persisted);
        assert!(debug_output.contains("PersistedKey"));
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("64 bytes"));

        // Test FileStore redacts sensitive data
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();
        store.init_with_password(b"test-password").unwrap();

        let debug_output = format!("{:?}", store);
        assert!(debug_output.contains("FileStore"));
        assert!(debug_output.contains("[SET]")); // master_key is set
        assert!(!debug_output.contains("test-password"));

        // Test SecretKey redacts bytes
        let secret = SecretKey::from_bytes(vec![0xAB; 32], Algorithm::Aes256Gcm).unwrap();
        let debug_output = format!("{:?}", secret);
        assert!(debug_output.contains("SecretKey"));
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("0xAB"));
    }

    #[test]
    fn test_file_store_export_import() {
        use crate::key::SecretKey;
        use crate::Algorithm;
        use tempfile::tempdir;

        // Create store
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();

        // Create and store a key
        let key_id = KeyId::from_bytes([99; 16]);
        let secret_key =
            SecretKey::from_bytes(vec![0x42; 32], Algorithm::ChaCha20Poly1305).unwrap();
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
            metadata,
        };
        store.store(versioned_key).unwrap();

        // Export the key
        let export_password = b"export-password-123";
        let exported = store.export_key(&key_id, export_password).unwrap();

        // Verify export structure
        assert_eq!(exported.metadata.algorithm, Algorithm::ChaCha20Poly1305);
        assert_eq!(exported.wrapping_algorithm, Algorithm::XChaCha20Poly1305);

        // Create a second store
        let temp_dir2 = tempdir().unwrap();
        let config2 = StorageConfig::default();
        let mut store2 = FileStore::new(temp_dir2.path(), config2).unwrap();

        // Import into second store
        let imported_id = store2.import_key(&exported, export_password).unwrap();
        assert_eq!(imported_id, key_id);

        // Verify the imported key
        let retrieved = store2.retrieve(&imported_id).unwrap();
        assert_eq!(retrieved.metadata.algorithm, Algorithm::ChaCha20Poly1305);
        assert_eq!(retrieved.metadata.version, 1);
        assert_eq!(retrieved.key.expose_secret(), &vec![0x42; 32]);
    }

    #[test]
    fn test_file_store_backup_restore() {
        use crate::backup::BackupConfig;
        use crate::key::SecretKey;
        use crate::Algorithm;
        use tempfile::tempdir;

        // Create original vault with multiple keys
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path(), config).unwrap();

        // Add multiple keys
        let key_id1 = KeyId::from_bytes([1; 16]);
        let secret_key1 =
            SecretKey::from_bytes(vec![0x11; 32], Algorithm::ChaCha20Poly1305).unwrap();
        let metadata1 = KeyMetadata {
            id: key_id1.clone(),
            base_id: key_id1.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        store
            .store(VersionedKey {
                key: secret_key1,
                metadata: metadata1,
            })
            .unwrap();

        let key_id2 = KeyId::from_bytes([2; 16]);
        let secret_key2 =
            SecretKey::from_bytes(vec![0x22; 32], Algorithm::XChaCha20Poly1305).unwrap();
        let metadata2 = KeyMetadata {
            id: key_id2.clone(),
            base_id: key_id2.clone(),
            algorithm: Algorithm::XChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        store
            .store(VersionedKey {
                key: secret_key2,
                metadata: metadata2,
            })
            .unwrap();

        // Create backup
        let backup_password = b"backup-password-123";
        let backup_config = BackupConfig {
            include_audit_logs: false,
            compress: true,
            encryption_password: backup_password.to_vec(),
            comment: Some("Test backup".to_string()),
        };

        let backup = store.backup(backup_password, backup_config).unwrap();

        // Verify backup metadata
        assert_eq!(backup.metadata.key_count, 2);
        assert!(backup.metadata.compressed);
        assert!(!backup.metadata.has_audit_logs);

        // Create new vault and restore
        let temp_dir2 = tempdir().unwrap();
        let config2 = StorageConfig::default();
        let mut store2 = FileStore::new(temp_dir2.path(), config2).unwrap();

        let restored_count = store2.restore(&backup, backup_password).unwrap();
        assert_eq!(restored_count, 2);

        // Verify restored keys
        let retrieved1 = store2.retrieve(&key_id1).unwrap();
        assert_eq!(retrieved1.key.expose_secret(), &vec![0x11; 32]);
        assert_eq!(retrieved1.metadata.algorithm, Algorithm::ChaCha20Poly1305);

        let retrieved2 = store2.retrieve(&key_id2).unwrap();
        assert_eq!(retrieved2.key.expose_secret(), &vec![0x22; 32]);
        assert_eq!(retrieved2.metadata.algorithm, Algorithm::XChaCha20Poly1305);
    }
}
