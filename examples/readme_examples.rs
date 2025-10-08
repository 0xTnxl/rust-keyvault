/// Verification that all README examples compile correctly
///
/// This file contains all the code snippets from README.md to ensure they work.
use rust_keyvault::backup::{BackupConfig, VaultBackup};
use rust_keyvault::export::ExportedKey;
use rust_keyvault::key::{SecretKey, VersionedKey};
use rust_keyvault::storage::*;
use rust_keyvault::*;
use std::time::SystemTime;

fn main() -> Result<()> {
    println!("Verifying README examples...\n");

    // Create temporary directory for testing
    let temp_dir = tempfile::tempdir()?;

    // ========================================
    // Example 1: Basic Usage
    // ========================================
    println!("1. Basic Usage Example");
    {
        let config = StorageConfig {
            encrypted: true,
            ..Default::default()
        };
        let mut store = FileStore::new(temp_dir.path().join("basic"), config)?;
        store.init_with_password(b"your-secure-password")?;

        // Generate a new key
        let base_id = KeyId::generate_base()?;
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;

        let metadata = KeyMetadata {
            id: base_id.clone(),
            base_id: base_id.clone(),
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

        // Store the key
        store.store(versioned_key)?;

        // Retrieve and use
        let retrieved = store.retrieve(&base_id)?;
        println!("   Key algorithm: {:?}", retrieved.key.algorithm());
    }

    // ========================================
    // Example 2: Key Rotation
    // ========================================
    println!("\n2. Key Rotation Example");
    {
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path().join("rotation"), config)?;

        // Create initial key
        let base_id = KeyId::generate_base()?;
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
        let metadata = KeyMetadata {
            id: base_id.clone(),
            base_id: base_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        store.store(VersionedKey {
            key: secret_key,
            metadata,
        })?;

        // Rotate to a new version
        let rotated_key = store.rotate_key(&base_id)?;
        println!("   New version: {}", rotated_key.metadata.version);

        // Get all versions
        let versions = store.get_key_versions(&base_id)?;
        println!("   Total versions: {}", versions.len());

        // Get latest active key
        let latest = store.get_latest_key(&base_id)?;
        println!("   Latest version: {}", latest.metadata.version);
    }

    // ========================================
    // Example 3: Import/Export
    // ========================================
    println!("\n3. Import/Export Example");
    {
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path().join("export"), config)?;

        // Create a key to export
        let base_id = KeyId::generate_base()?;
        let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
        let metadata = KeyMetadata {
            id: base_id.clone(),
            base_id: base_id.clone(),
            algorithm: Algorithm::ChaCha20Poly1305,
            created_at: SystemTime::now(),
            expires_at: None,
            state: KeyState::Active,
            version: 1,
        };
        store.store(VersionedKey {
            key: secret_key,
            metadata,
        })?;

        // Export key with password protection
        let exported = store.export_key(&base_id, b"export-password")?;

        // Serialize to JSON for transmission/storage
        let json_export = exported.to_json()?;
        let export_file = temp_dir.path().join("exported_key.json");
        std::fs::write(&export_file, &json_export)?;
        println!("   Exported to JSON: {} bytes", json_export.len());

        // Import into another vault
        let mut target_store =
            FileStore::new(temp_dir.path().join("target"), StorageConfig::default())?;

        // Deserialize from JSON
        let json_str = std::fs::read_to_string(&export_file)?;
        let exported_key = ExportedKey::from_json(&json_str)?;

        // Import the key
        let imported_id = target_store.import_key(&exported_key, b"export-password")?;
        println!("   ✓ Imported key with ID: {}", imported_id);
    }

    // ========================================
    // Example 4: Backup/Restore
    // ========================================
    println!("\n4. Backup/Restore Example");
    {
        let config = StorageConfig::default();
        let mut store = FileStore::new(temp_dir.path().join("backup"), config)?;

        // Create some keys
        for i in 0..3 {
            let base_id = KeyId::from_bytes([i; 16]);
            let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
            let metadata = KeyMetadata {
                id: base_id.clone(),
                base_id: base_id.clone(),
                algorithm: Algorithm::ChaCha20Poly1305,
                created_at: SystemTime::now(),
                expires_at: None,
                state: KeyState::Active,
                version: 1,
            };
            store.store(VersionedKey {
                key: secret_key,
                metadata,
            })?;
        }

        // Configure backup options
        let backup_config = BackupConfig {
            include_audit_logs: true,
            compress: true,
            encryption_password: b"backup-password".to_vec(),
            comment: Some("Production backup".to_string()),
        };

        // Create encrypted backup (this will take ~10s due to Argon2)
        println!("   Creating backup (takes ~10s due to Argon2)...");
        let backup = store.backup(b"backup-password", backup_config)?;

        // Serialize to JSON and save
        let backup_json = backup.to_json()?;
        let backup_file = temp_dir.path().join("vault.backup.json");
        std::fs::write(&backup_file, &backup_json)?;
        println!("   Backup created: {} bytes", backup_json.len());

        // Restore from backup (this will also take ~10s due to Argon2)
        println!("   Restoring backup (takes ~10s due to Argon2)...");
        let backup_str = std::fs::read_to_string(&backup_file)?;
        let backup = VaultBackup::from_json(&backup_str)?;

        let mut restored_store =
            FileStore::new(temp_dir.path().join("restored"), StorageConfig::default())?;
        let restored_count = restored_store.restore(&backup, b"backup-password")?;
        println!("   Restored {} keys", restored_count);
    }

    println!("\nAll README examples verified successfully!");
    Ok(())
}
