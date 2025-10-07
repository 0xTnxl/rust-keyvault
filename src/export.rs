//! Key import/export functionality for secure key exchange


use crate::{Algorithm, KeyMetadata, Result, key::SecretKey};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Current version of the export format
pub const EXPORT_FORMAT_VERSION: u32 = 1;

/// A cryptographic key exported in a secure, portable format
/// 
/// The key material is encrypted using a password-derived key (Argon2id).
/// The format is versioned to support future compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKey {
    /// Format version for compatibility
    pub format_version: u32,
    
    /// When the key was exported
    pub exported_at: SystemTime,
    
    /// Algorithm used to wrap/encrypt the key
    pub wrapping_algorithm: Algorithm,
    
    /// Salt used for password derivation (32 bytes)
    pub salt: Vec<u8>,
    
    /// Argon2 parameters used for derivation
    pub argon2_params: ExportArgon2Params,
    
    /// Encrypted key material (nonce + ciphertext + tag)
    pub encrypted_key: Vec<u8>,
    
    /// Key metadata (stored in plaintext for validation)
    pub metadata: KeyMetadata,
    
    /// Optional comment/description
    pub comment: Option<String>,
}

/// Argon2 parameters used for export encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportArgon2Params {
    /// Memory size in KiB
    pub memory_kib: u32,
    /// Number of iterations
    pub time_cost: u32,
    /// Degree of parallelism
    pub parallelism: u32,
}

impl ExportedKey {
    /// Create a new exported key structure
    pub fn new(
        key: &SecretKey,
        metadata: KeyMetadata,
        password: &[u8],
        wrapping_algorithm: Algorithm,
    ) -> Result<Self> {
        use crate::crypto::{RuntimeAead, RandomNonceGenerator, AEAD, NonceGenerator};
        use argon2::{Argon2, Algorithm as Argon2Algorithm, Params, Version};
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        
        // Generate random salt for this export
        let mut rng = ChaCha20Rng::from_entropy();
        let mut salt = vec![0u8; 32];
        rng.fill_bytes(&mut salt);
        
        // High-security Argon2 parameters for export
        let argon2_params = ExportArgon2Params {
            memory_kib: 65536, // 64 MiB
            time_cost: 4,
            parallelism: 4,
        };
        
        // Derive wrapping key from password
        let params = Params::new(
            argon2_params.memory_kib,
            argon2_params.time_cost,
            argon2_params.parallelism,
            Some(32),
        ).map_err(|e| crate::Error::crypto("export_key", &format!("invalid Argon2 params: {}", e)))?;
        
        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
        let mut wrapping_key_bytes = [0u8; 32];
        argon2.hash_password_into(password, &salt, &mut wrapping_key_bytes)
            .map_err(|e| crate::Error::crypto("export_key", &format!("Argon2 derivation failed: {}", e)))?;
        
        let wrapping_key = SecretKey::from_bytes(
            wrapping_key_bytes.to_vec(),
            wrapping_algorithm,
        )?;
        
        // Encrypt the key material
        let aead = RuntimeAead;
        let nonce_size = match wrapping_algorithm {
            Algorithm::XChaCha20Poly1305 => 24,
            _ => 12,
        };
        
        let mut nonce_gen = RandomNonceGenerator::new(
            ChaCha20Rng::from_entropy(),
            nonce_size
        );
        
        let nonce = nonce_gen.generate_nonce(b"key-export")?;
        let ciphertext = aead.encrypt(
            &wrapping_key,
            &nonce,
            key.expose_secret(),
            b"rust-keyvault-export-v1",
        )?;
        
        // Prepend nonce to ciphertext
        let mut encrypted_key = nonce;
        encrypted_key.extend_from_slice(&ciphertext);
        
        Ok(Self {
            format_version: EXPORT_FORMAT_VERSION,
            exported_at: SystemTime::now(),
            wrapping_algorithm,
            salt,
            argon2_params,
            encrypted_key,
            metadata,
            comment: None,
        })
    }
    
    /// Decrypt and extract the key material
    pub fn decrypt(&self, password: &[u8]) -> Result<SecretKey> {
        use crate::crypto::{RuntimeAead, AEAD};
        use argon2::{Argon2, Algorithm as Argon2Algorithm, Params, Version};
        
        // Verify format version
        if self.format_version != EXPORT_FORMAT_VERSION {
            return Err(crate::Error::SerializationError {
                operation: "import_key".to_string(),
                message: format!(
                    "unsupported export format version: {} (expected {})",
                    self.format_version, EXPORT_FORMAT_VERSION
                ),
            });
        }
        
        // Derive wrapping key from password
        let params = Params::new(
            self.argon2_params.memory_kib,
            self.argon2_params.time_cost,
            self.argon2_params.parallelism,
            Some(32),
        ).map_err(|e| crate::Error::crypto("import_key", &format!("invalid Argon2 params: {}", e)))?;
        
        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
        let mut wrapping_key_bytes = [0u8; 32];
        argon2.hash_password_into(password, &self.salt, &mut wrapping_key_bytes)
            .map_err(|e| crate::Error::crypto("import_key", &format!("Argon2 derivation failed: {}", e)))?;
        
        let wrapping_key = SecretKey::from_bytes(
            wrapping_key_bytes.to_vec(),
            self.wrapping_algorithm,
        )?;
        
        // Determine nonce size
        let nonce_size = match self.wrapping_algorithm {
            Algorithm::XChaCha20Poly1305 => 24,
            _ => 12,
        };
        
        if self.encrypted_key.len() < nonce_size {
            return Err(crate::Error::crypto("import_key", "encrypted key too short"));
        }
        
        // Split nonce and ciphertext
        let (nonce, ciphertext) = self.encrypted_key.split_at(nonce_size);
        
        // Decrypt the key material
        let aead = RuntimeAead;
        let key_bytes = aead.decrypt(
            &wrapping_key,
            nonce,
            ciphertext,
            b"rust-keyvault-export-v1",
        )?;
        
        // Reconstruct the secret key
        SecretKey::from_bytes(key_bytes, self.metadata.algorithm)
    }
    
    /// Add a comment to the exported key
    pub fn with_comment<S: Into<String>>(mut self, comment: S) -> Self {
        self.comment = Some(comment.into());
        self
    }
    
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::SerializationError {
                operation: "export_to_json".to_string(),
                message: format!("JSON serialization failed: {}", e),
            })
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::Error::SerializationError {
                operation: "import_from_json".to_string(),
                message: format!("JSON deserialization failed: {}", e),
            })
    }
    
    /// Serialize to bytes (using bincode or similar)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| crate::Error::SerializationError {
                operation: "export_to_bytes".to_string(),
                message: format!("serialization failed: {}", e),
            })
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::Error::SerializationError {
                operation: "import_from_bytes".to_string(),
                message: format!("deserialization failed: {}", e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyId;
    use std::time::SystemTime;
    
    #[test]
    fn test_export_import_roundtrip() {
        // Create a test key
        let key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let key_id = KeyId::generate_base().unwrap();
        
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: crate::KeyState::Active,
            version: 1,
        };
        
        // Export with password
        let password = b"super-secret-export-password";
        let exported = ExportedKey::new(&key, metadata.clone(), password, Algorithm::ChaCha20Poly1305)
            .unwrap()
            .with_comment("Test export");
        
        // Verify exported structure
        assert_eq!(exported.format_version, EXPORT_FORMAT_VERSION);
        assert_eq!(exported.wrapping_algorithm, Algorithm::ChaCha20Poly1305);
        assert_eq!(exported.metadata.algorithm, Algorithm::ChaCha20Poly1305);
        assert!(exported.comment.is_some());
        
        // Decrypt with correct password
        let decrypted = exported.decrypt(password).unwrap();
        assert_eq!(decrypted.expose_secret(), key.expose_secret());
        assert_eq!(decrypted.algorithm(), key.algorithm());
    }
    
    #[test]
    fn test_wrong_password_fails() {
        let key = SecretKey::generate(Algorithm::Aes256Gcm).unwrap();
        let key_id = KeyId::generate_base().unwrap();
        
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id,
            algorithm: Algorithm::Aes256Gcm,
            created_at: SystemTime::now(),
            expires_at: None,
            state: crate::KeyState::Active,
            version: 1,
        };
        
        let exported = ExportedKey::new(&key, metadata, b"correct-password", Algorithm::Aes256Gcm).unwrap();
        
        // Try to decrypt with wrong password
        let result = exported.decrypt(b"wrong-password");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_json_serialization() {
        let key = SecretKey::generate(Algorithm::XChaCha20Poly1305).unwrap();
        let key_id = KeyId::generate_base().unwrap();
        
        let metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id,
            algorithm: Algorithm::XChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: crate::KeyState::Active,
            version: 1,
        };
        
        let exported = ExportedKey::new(&key, metadata, b"password", Algorithm::XChaCha20Poly1305).unwrap();
        
        // Serialize to JSON
        let json = exported.to_json().unwrap();
        assert!(json.contains("format_version"));
        assert!(json.contains("encrypted_key"));
        
        // Deserialize from JSON
        let imported = ExportedKey::from_json(&json).unwrap();
        assert_eq!(imported.format_version, exported.format_version);
        assert_eq!(imported.metadata.algorithm, exported.metadata.algorithm);
        
        // Verify decryption still works
        let decrypted = imported.decrypt(b"password").unwrap();
        assert_eq!(decrypted.expose_secret(), key.expose_secret());
    }
    
    #[test]
    fn test_metadata_preserved() {
        let key = SecretKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let key_id = KeyId::generate_base().unwrap();
        
        let original_metadata = KeyMetadata {
            id: key_id.clone(),
            base_id: key_id,
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: Some(SystemTime::now()),
            state: crate::KeyState::Rotating,
            version: 42,
        };
        
        let exported = ExportedKey::new(&key, original_metadata.clone(), b"pass", Algorithm::ChaCha20Poly1305).unwrap();
        
        // Verify metadata is preserved
        assert_eq!(exported.metadata.version, 42);
        assert_eq!(exported.metadata.state, crate::KeyState::Rotating);
        assert!(exported.metadata.expires_at.is_some());
    }
}
