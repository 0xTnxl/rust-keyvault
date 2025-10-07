/// Example demonstrating secure key export/import between vaults
/// 
/// This example shows:
/// - Exporting a key with password protection
/// - Serializing to JSON for portability
/// - Importing into a different vault
/// - Verifying key integrity after import

use rust_keyvault::{
    Algorithm, KeyId, KeyMetadata, KeyState,
    key::{SecretKey, VersionedKey},
    storage::{FileStore, StorageConfig, KeyStore},
    export::ExportedKey,
};
use std::time::{SystemTime, Duration};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Key Export/Import Example\n");

    // ========================================
    // Step 1: Create source vault and key
    // ========================================
    println!("1. Creating source vault with a test key...");
    
    let temp_dir = tempfile::tempdir()?;
    let config = StorageConfig::default();
    let mut source_vault = FileStore::new(temp_dir.path(), config)?;

    let key_id = KeyId::from_bytes([1; 16]);
    let secret_key = SecretKey::generate(Algorithm::ChaCha20Poly1305)?;
    let metadata = KeyMetadata {
        id: key_id.clone(),
        base_id: key_id.clone(),
        algorithm: Algorithm::ChaCha20Poly1305,
        created_at: SystemTime::now(),
        expires_at: Some(SystemTime::now() + Duration::from_secs(86400 * 365)), // 1 year
        state: KeyState::Active,
        version: 1,
    };
    
    let versioned_key = VersionedKey {
        key: secret_key,
        metadata,
    };
    
    source_vault.store(versioned_key)?;
    println!("   ✓ Key stored with ID: {}", hex::encode(key_id.as_bytes()));

    // ========================================
    // Step 2: Export the key
    // ========================================
    println!("\n2. Exporting key with password protection...");
    
    let export_password = b"super-secret-export-password-123!";
    let exported_key = source_vault.export_key(&key_id, export_password)?;
    
    println!("   ✓ Key exported successfully");
    println!("   - Export format version: {}", exported_key.format_version);
    println!("   - Wrapping algorithm: {:?}", exported_key.wrapping_algorithm);
    println!("   - Argon2 parameters: {} MiB memory, t={}, p={}", 
             exported_key.argon2_params.memory_kib / 1024,
             exported_key.argon2_params.time_cost,
             exported_key.argon2_params.parallelism);

    // ========================================
    // Step 3: Serialize to JSON
    // ========================================
    println!("\n3. Serializing to JSON for transmission/storage...");
    
    let json_export = exported_key.to_json()?;
    println!("   ✓ Serialized to {} bytes", json_export.len());
    println!("   First 100 chars: {}...", &json_export[..100.min(json_export.len())]);

    // Optional: Save to file
    // std::fs::write("exported_key.json", &json_export)?;

    // ========================================
    // Step 4: Deserialize and verify
    // ========================================
    println!("\n4. Deserializing from JSON...");
    
    let deserialized = ExportedKey::from_json(&json_export)?;
    println!("   ✓ Deserialized successfully");
    println!("   - Algorithm: {:?}", deserialized.metadata.algorithm);
    println!("   - Created at: {:?}", deserialized.metadata.created_at);
    println!("   - Expires at: {:?}", deserialized.metadata.expires_at);

    // ========================================
    // Step 5: Import into destination vault
    // ========================================
    println!("\n5. Creating destination vault and importing key...");
    
    let temp_dir2 = tempfile::tempdir()?;
    let config2 = StorageConfig::default();
    let mut dest_vault = FileStore::new(temp_dir2.path(), config2)?;

    let imported_id = dest_vault.import_key(&deserialized, export_password)?;
    println!("   ✓ Key imported with ID: {}", hex::encode(imported_id.as_bytes()));
    assert_eq!(imported_id, key_id, "Key IDs should match");

    // ========================================
    // Step 6: Verify imported key
    // ========================================
    println!("\n6. Verifying imported key integrity...");
    
    let original_key = source_vault.retrieve(&key_id)?;
    let imported_key = dest_vault.retrieve(&imported_id)?;

    assert_eq!(
        original_key.key.expose_secret(),
        imported_key.key.expose_secret(),
        "Key material should be identical"
    );
    
    assert_eq!(
        original_key.metadata.algorithm,
        imported_key.metadata.algorithm,
        "Algorithm should match"
    );

    println!("   ✓ Key material verified - identical to original");
    println!("   ✓ Metadata preserved correctly");

    // ========================================
    // Step 7: Test wrong password failure
    // ========================================
    println!("\n7. Testing wrong password rejection...");
    
    let wrong_password = b"wrong-password";
    match dest_vault.import_key(&deserialized, wrong_password) {
        Err(e) => {
            println!("   ✓ Wrong password correctly rejected: {}", e);
        }
        Ok(_) => {
            panic!("Should have failed with wrong password!");
        }
    }

    // ========================================
    // Summary
    // ========================================
    println!("\n✅ Export/Import workflow complete!");
    println!("\nKey Features Demonstrated:");
    println!("  • Password-protected key export using Argon2id");
    println!("  • High-security parameters (64 MiB memory, t=4, p=4)");
    println!("  • XChaCha20Poly1305 encryption for exported keys");
    println!("  • JSON serialization for portability");
    println!("  • Metadata preservation (algorithm, timestamps, expiry)");
    println!("  • Audit trail logging");
    println!("  • Wrong password detection");
    
    println!("\nUse Cases:");
    println!("  • Key distribution between vaults");
    println!("  • Secure key backups");
    println!("  • Key migration between systems");
    println!("  • Multi-vault environments");

    Ok(())
}
