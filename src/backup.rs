//! Backup and restore functionality

use crate::{Algorithm, Error, Result};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Current version of the backup format
pub const BACKUP_FORMAT_VERSION: u32 = 1;

/// Configuration for creating a backup
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Include audit logs in the backup
    pub include_audit_logs: bool,

    /// Compress the backup data (reduces size by ~60-70%)
    pub compress: bool,

    /// Password for encrypting the backup
    pub encryption_password: Vec<u8>,

    /// Optional comment/description
    pub comment: Option<String>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            include_audit_logs: true,
            compress: true,
            encryption_password: Vec::new(),
            comment: None,
        }
    }
}

/// Metadata about a backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// When the backup was created
    pub created_at: SystemTime,

    /// Number of keys in the backup
    pub key_count: usize,

    /// Backup format version
    pub format_version: u32,

    /// HMAC checksum for integrity verification
    pub checksum: Vec<u8>,

    /// Whether the backup is compressed
    pub compressed: bool,

    /// Whether audit logs are included
    pub has_audit_logs: bool,

    /// Optional comment/description
    pub comment: Option<String>,

    /// Size of encrypted data in bytes
    pub data_size: usize,
}

/// Argon2 parameters for backup encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupArgon2Params {
    /// Memory size in KiB (default: 64 MiB = 65536 KiB)
    pub memory_kib: u32,
    /// Number of iterations (default: 4)
    pub time_cost: u32,
    /// Degree of parallelism (default: 4)
    pub parallelism: u32,
}

impl Default for BackupArgon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            time_cost: 4,
            parallelism: 4,
        }
    }
}

/// A complete encrypted backup of a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackup {
    /// Backup format version
    pub format_version: u32,

    /// Backup metadata
    pub metadata: BackupMetadata,

    /// Salt for password derivation (32 bytes)
    pub salt: Vec<u8>,

    /// Argon2 parameters used
    pub argon2_params: BackupArgon2Params,

    /// Algorithm used for encryption
    pub encryption_algorithm: Algorithm,

    /// Encrypted backup data (nonce + ciphertext + tag)
    pub encrypted_data: Vec<u8>,
}

/// Internal structure for backup data before encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    /// All exported keys from the vault
    pub keys: Vec<crate::export::ExportedKey>,

    /// Audit log entries (if included)
    pub audit_logs: Option<Vec<crate::audit::AuditEvent>>,

    /// Vault metadata (creation time, etc.)
    pub vault_info: VaultInfo,
}

/// Information about the vault being backed up
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    /// When the vault was created
    pub created_at: SystemTime,

    /// Total number of operations performed
    pub operation_count: u64,
}

impl VaultBackup {
    /// Create a new encrypted backup
    pub fn new(backup_data: &BackupData, password: &[u8], config: &BackupConfig) -> Result<Self> {
        use crate::crypto::{NonceGenerator, RandomNonceGenerator, RuntimeAead, AEAD};
        use argon2::{Algorithm as Argon2Algo, Argon2, Params, Version};
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        // Generate random salt
        let mut salt = vec![0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);

        // Serialize backup data
        let serialized = serde_json::to_vec(backup_data)
            .map_err(|e| Error::storage(format!("serialize_backup: {}", e), String::new()))?;

        // Compress if requested
        let data_to_encrypt = if config.compress {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&serialized).map_err(|e| {
                Error::storage("compress_backup", &format!("compression failed: {}", e))
            })?;
            encoder.finish().map_err(|e| {
                Error::storage("compress_backup", &format!("compression failed: {}", e))
            })?
        } else {
            serialized
        };

        // Derive encryption key using Argon2id
        let argon2_params = BackupArgon2Params::default();
        let params = Params::new(
            argon2_params.memory_kib,
            argon2_params.time_cost,
            argon2_params.parallelism,
            Some(32), // 256-bit key
        )
        .map_err(|e| Error::crypto("derive_backup_key", &format!("Argon2 error: {}", e)))?;

        let argon2 = Argon2::new(Argon2Algo::Argon2id, Version::V0x13, params);
        let mut derived_key = vec![0u8; 32];
        argon2
            .hash_password_into(password, &salt, &mut derived_key)
            .map_err(|e| Error::crypto("derive_backup_key", &format!("Argon2 error: {}", e)))?;

        // Create a SecretKey for encryption
        let encryption_algorithm = Algorithm::XChaCha20Poly1305;
        let wrapping_key =
            crate::key::SecretKey::from_bytes(derived_key.clone(), encryption_algorithm)?;

        // Encrypt using RuntimeAead
        let aead = RuntimeAead;
        let nonce_size = 24; // XChaCha20Poly1305 uses 24-byte nonces

        let mut nonce_gen = RandomNonceGenerator::new(ChaCha20Rng::from_entropy(), nonce_size);

        let nonce = nonce_gen.generate_nonce(b"vault-backup")?;
        let ciphertext = aead.encrypt(&wrapping_key, &nonce, &data_to_encrypt, &[])?;

        // Combine nonce + ciphertext
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        // Calculate HMAC for integrity
        let checksum = Self::calculate_hmac(&encrypted_data, &derived_key)?;

        let metadata = BackupMetadata {
            created_at: SystemTime::now(),
            key_count: backup_data.keys.len(),
            format_version: BACKUP_FORMAT_VERSION,
            checksum: checksum.clone(),
            compressed: config.compress,
            has_audit_logs: backup_data.audit_logs.is_some(),
            comment: config.comment.clone(),
            data_size: encrypted_data.len(),
        };

        Ok(Self {
            format_version: BACKUP_FORMAT_VERSION,
            metadata,
            salt,
            argon2_params,
            encryption_algorithm,
            encrypted_data,
        })
    }

    /// Decrypt and restore a backup
    pub fn decrypt(&self, password: &[u8]) -> Result<BackupData> {
        use crate::crypto::{RuntimeAead, AEAD};
        use argon2::{Algorithm as Argon2Algo, Argon2, Params, Version};

        // Derive decryption key
        let params = Params::new(
            self.argon2_params.memory_kib,
            self.argon2_params.time_cost,
            self.argon2_params.parallelism,
            Some(32),
        )
        .map_err(|e| Error::crypto("derive_backup_key", &format!("Argon2 error: {}", e)))?;

        let argon2 = Argon2::new(Argon2Algo::Argon2id, Version::V0x13, params);
        let mut derived_key = vec![0u8; 32];
        argon2
            .hash_password_into(password, &self.salt, &mut derived_key)
            .map_err(|e| Error::crypto("derive_backup_key", &format!("Argon2 error: {}", e)))?;

        // Verify HMAC
        let calculated_hmac = Self::calculate_hmac(&self.encrypted_data, &derived_key)?;
        if calculated_hmac != self.metadata.checksum {
            return Err(Error::crypto(
                "verify_backup_hmac",
                "HMAC verification failed - backup may be corrupted",
            ));
        }

        // Extract nonce and ciphertext
        let nonce_size = match self.encryption_algorithm {
            Algorithm::XChaCha20Poly1305 => 24,
            Algorithm::ChaCha20Poly1305 | Algorithm::Aes256Gcm => 12,
            _ => {
                return Err(Error::crypto(
                    "unsupported_algorithm",
                    "unsupported encryption algorithm for backup",
                ))
            }
        };

        if self.encrypted_data.len() < nonce_size {
            return Err(Error::crypto("decrypt_backup", "encrypted data too short"));
        }

        let (nonce, ciphertext) = self.encrypted_data.split_at(nonce_size);

        // Create a SecretKey for decryption
        let wrapping_key =
            crate::key::SecretKey::from_bytes(derived_key.clone(), self.encryption_algorithm)?;

        // Decrypt
        let aead = RuntimeAead;
        let decrypted = aead.decrypt(&wrapping_key, nonce, ciphertext, &[])?;

        // Decompress if needed
        let decompressed = if self.metadata.compressed {
            use flate2::read::GzDecoder;
            use std::io::Read;

            let mut decoder = GzDecoder::new(&decrypted[..]);
            let mut result = Vec::new();
            decoder.read_to_end(&mut result).map_err(|e| {
                Error::storage("decompress_backup", &format!("decompression failed: {}", e))
            })?;
            result
        } else {
            decrypted
        };

        // Deserialize
        serde_json::from_slice(&decompressed).map_err(|e| {
            Error::storage(
                "deserialize_backup",
                &format!("deserialization failed: {}", e),
            )
        })
    }

    /// Calculate HMAC-SHA256 for integrity verification
    fn calculate_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| Error::crypto("create_hmac", &format!("HMAC error: {}", e)))?;

        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Serialize backup to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            Error::storage("serialize_backup", &format!("serialization failed: {}", e))
        })
    }

    /// Deserialize backup from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            Error::storage(
                "deserialize_backup",
                &format!("deserialization failed: {}", e),
            )
        })
    }

    /// Serialize backup to binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            Error::storage("serialize_backup", &format!("serialization failed: {}", e))
        })
    }

    /// Deserialize backup from binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            Error::storage(
                "deserialize_backup",
                &format!("deserialization failed: {}", e),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{export::ExportedKey, key::SecretKey, KeyId, KeyMetadata, KeyState};

    fn create_test_backup_data() -> BackupData {
        let key_id = KeyId::generate_base().unwrap();
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };

        let exported_key = ExportedKey::new(
            &secret_key,
            metadata,
            b"test-password",
            Algorithm::XChaCha20Poly1305,
        )
        .unwrap();

        BackupData {
            keys: vec![exported_key],
            audit_logs: None,
            vault_info: VaultInfo {
                created_at: SystemTime::now(),
                operation_count: 42,
            },
        }
    }

    #[test]
    fn test_backup_encrypt_decrypt() {
        let backup_data = create_test_backup_data();
        let password = b"backup-password-123";

        let config = BackupConfig {
            include_audit_logs: false,
            compress: true,
            encryption_password: password.to_vec(),
            comment: Some("Test backup".to_string()),
        };

        // Encrypt
        let backup = VaultBackup::new(&backup_data, password, &config).unwrap();

        assert_eq!(backup.format_version, BACKUP_FORMAT_VERSION);
        assert_eq!(backup.metadata.key_count, 1);
        assert!(backup.metadata.compressed);
        assert!(!backup.metadata.has_audit_logs);

        // Decrypt
        let decrypted = backup.decrypt(password).unwrap();

        assert_eq!(decrypted.keys.len(), 1);
        assert!(decrypted.audit_logs.is_none());
        assert_eq!(decrypted.vault_info.operation_count, 42);
    }

    #[test]
    fn test_backup_wrong_password() {
        let backup_data = create_test_backup_data();
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let config = BackupConfig::default();
        let backup = VaultBackup::new(&backup_data, password, &config).unwrap();

        // Should fail with wrong password
        assert!(backup.decrypt(wrong_password).is_err());
    }

    #[test]
    fn test_backup_json_serialization() {
        let backup_data = create_test_backup_data();
        let password = b"test-password";

        let config = BackupConfig::default();
        let backup = VaultBackup::new(&backup_data, password, &config).unwrap();

        // Serialize to JSON
        let json = backup.to_json().unwrap();
        assert!(json.contains("format_version"));
        assert!(json.contains("encrypted_data"));

        // Deserialize
        let deserialized = VaultBackup::from_json(&json).unwrap();

        // Verify can still decrypt
        let decrypted = deserialized.decrypt(password).unwrap();
        assert_eq!(decrypted.keys.len(), 1);
    }

    #[test]
    fn test_backup_hmac_verification() {
        let backup_data = create_test_backup_data();
        let password = b"test-password";

        let config = BackupConfig::default();
        let mut backup = VaultBackup::new(&backup_data, password, &config).unwrap();

        // Corrupt the encrypted data
        if let Some(byte) = backup.encrypted_data.get_mut(10) {
            *byte = byte.wrapping_add(1);
        }

        // Should fail HMAC verification
        let result = backup.decrypt(password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HMAC"));
    }

    #[test]
    fn test_backup_compression() {
        let backup_data = create_test_backup_data();
        let password = b"test-password";

        // Create compressed backup
        let config_compressed = BackupConfig {
            compress: true,
            ..Default::default()
        };
        let backup_compressed =
            VaultBackup::new(&backup_data, password, &config_compressed).unwrap();

        // Create uncompressed backup
        let config_uncompressed = BackupConfig {
            compress: false,
            ..Default::default()
        };
        let backup_uncompressed =
            VaultBackup::new(&backup_data, password, &config_uncompressed).unwrap();

        // Compressed should be smaller (usually 60-70% reduction)
        assert!(backup_compressed.encrypted_data.len() < backup_uncompressed.encrypted_data.len());

        // Both should decrypt successfully
        assert!(backup_compressed.decrypt(password).is_ok());
        assert!(backup_uncompressed.decrypt(password).is_ok());
    }
}
