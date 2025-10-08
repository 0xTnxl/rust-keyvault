# rust-keyvault

[![Crates.io](https://img.shields.io/crates/v/rust-keyvault.svg)](https://crates.io/crates/rust-keyvault)
[![Documentation](https://docs.rs/rust-keyvault/badge.svg)](https://docs.rs/rust-keyvault)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/0xTnxl/rust-keyvault#license)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)

A secure, production-grade cryptographic key management library for Rust.

## Features

- **Secure Key Storage** - Encrypted at-rest with Argon2id + XChaCha20-Poly1305
- **Key Rotation** - Seamless key lifecycle management with versioning
- **Persistent Storage** - File-based backend with optional encryption
- **Import/Export** - Secure key exchange between vaults (new in v0.2.0!)
- **Backup/Restore** - Encrypted vault backups with compression (new in v0.2.0!)
- **Audit Logging** - Comprehensive security event tracking
- **High Performance** - ~2.4µs key generation, efficient storage
- **Memory Safety** - Automatic secret zeroization, constant-time operations
- **Thread-Safe** - Concurrent access with RwLock protection
- **Benchmarked** - Performance baselines established with Criterion

## Security

- **Zero Unsafe Code:** `#![forbid(unsafe_code)]` - completely memory safe
- **Security Audit:** ✅ Passed (October 2025) - see [SECURITY.md](SECURITY.md)
- **OWASP Compliant:** Argon2id parameters meet OWASP 2024 guidelines
- **Constant-Time Operations:** Timing-attack resistant comparisons
- **Automatic Zeroization:** Secrets cleared from memory on drop

## Supported Algorithms

| Algorithm | Type | Key Size | Nonce Size | Use Case |
|-----------|------|----------|------------|----------|
| **ChaCha20-Poly1305** | AEAD | 256-bit | 96-bit | General encryption |
| **XChaCha20-Poly1305** | AEAD | 256-bit | 192-bit | Safe random nonces |
| **AES-256-GCM** | AEAD | 256-bit | 96-bit | Hardware acceleration |
| **Ed25519** | Signature | 256-bit | - | Digital signatures* |
| **X25519** | Key Exchange | 256-bit | - | ECDH key agreement* |

*Asymmetric algorithms partially implemented - full support in v0.3.0

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-keyvault = "0.2.0"
```

### Basic Usage

```rust
use rust_keyvault::*;
use rust_keyvault::key::{SecretKey, VersionedKey};
use rust_keyvault::storage::*;
use std::time::SystemTime;

// Create an encrypted file store
let config = StorageConfig { encrypted: true, ..Default::default() };
let mut store = FileStore::new("./keys", config)?;
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

let versioned_key = VersionedKey { key: secret_key, metadata };

// Store the key
store.store(versioned_key)?;

// Retrieve and use
let retrieved = store.retrieve(&base_id)?;
println!("Key algorithm: {:?}", retrieved.key.algorithm());
```

### Key Rotation

```rust
// Rotate to a new version
let rotated_key = store.rotate_key(&base_id)?;
println!("New version: {}", rotated_key.metadata.version); // 2

// Get all versions
let versions = store.get_key_versions(&base_id)?;
println!("Total versions: {}", versions.len()); // 2

// Get latest active key
let latest = store.get_latest_key(&base_id)?;
```

### Import/Export (v0.2.0)

```rust
use rust_keyvault::export::ExportedKey;
use rust_keyvault::storage::FileStore;

// Export key with password protection
let exported = store.export_key(&base_id, b"export-password")?;

// Serialize to JSON for transmission/storage
let json_export = exported.to_json()?;
std::fs::write("exported_key.json", &json_export)?;

// Import into another vault
let mut target_store = FileStore::new("./target", config)?;

// Deserialize from JSON
let json_str = std::fs::read_to_string("exported_key.json")?;
let exported_key = ExportedKey::from_json(&json_str)?;

// Import the key
let imported_id = target_store.import_key(&exported_key, b"export-password")?;
println!("Imported key with ID: {}", imported_id);
```

### Backup/Restore (v0.2.0)

```rust
use rust_keyvault::backup::{BackupConfig, VaultBackup};

// Configure backup options
let backup_config = BackupConfig {
    include_audit_logs: true,
    compress: true,
    encryption_password: b"backup-password".to_vec(),
    comment: Some("Production backup".to_string()),
};

// Create encrypted backup
let backup = store.backup(b"backup-password", backup_config)?;

// Serialize to JSON and save
let backup_json = backup.to_json()?;
std::fs::write("vault.backup.json", &backup_json)?;

// Restore from backup
let backup_str = std::fs::read_to_string("vault.backup.json")?;
let backup = VaultBackup::from_json(&backup_str)?;

let mut restored_store = FileStore::new("./restored", config)?;
let restored_count = restored_store.restore(&backup, b"backup-password")?;
println!("Restored {} keys", restored_count);
```

## ⚡ Performance

Benchmarks run on AMD Ryzen 9 5950X (3.4 GHz base):

| Operation | Time | Throughput |
|-----------|------|------------|
| Key Generation (ChaCha20) | ~2.4 µs | ~416k keys/sec |
| Key Generation (AES-256) | ~2.1 µs | ~476k keys/sec |
| MemoryStore (retrieve) | ~500 ns | ~2M ops/sec |
| FileStore (store) | ~5-10 ms | ~100-200 ops/sec |
| Vault Backup (compressed) | ~8 ms | ~125 backups/sec |
| Key Export (encrypted) | ~65 ms | ~15 exports/sec |

*Full benchmark suite: `cargo bench`*

## Architecture

```
┌─────────────────┐
│  Applications   │
└─────────────────┘
         │
┌─────────────────────────────────────────┐
│     Core Key Management Layer           │
│  ┌─────────────┐    ┌────────────────┐  │
│  │  KeyStore   │    │ EncryptedStore │  │
│  │   Traits    │    │    Traits      │  │
│  └─────────────┘    └────────────────┘  │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ MemoryStore │    │   FileStore    │  │
│  │  (Testing)  │    │  (Production)  │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
         │
┌─────────────────────────────────────────┐
│    Import/Export & Backup Layer         │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ Key Export  │    │ Vault Backup   │  │
│  │ (Encrypted) │    │ (Compressed)   │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
         │
┌─────────────────────────────────────────┐
│      Cryptographic Primitives           │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ AEAD Crypto │    │   Argon2 KDF   │  │
│  │ ChaCha/AES  │    │  Derivation    │  │
│  └─────────────┘    └────────────────┘  │
│  ┌─────────────┐    ┌────────────────┐  │
│  │  HKDF/HMAC  │    │  Zeroization   │  │
│  │ Derivation  │    │  Memory Safe   │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
```

## Security Features

- **Modern Cryptography**: ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM AEAD
- **Memory Safety**: Automatic secret zeroization with `zeroize` crate
- **Key Derivation**: Argon2id (64 MiB memory, t=4) password-based KDF
- **HKDF**: HMAC-SHA256 based key derivation for domain separation
- **Authenticated Encryption**: Built-in integrity protection with HMAC-SHA256
- **Constant-Time Operations**: Timing-attack resistant key comparisons
- **Secure Random**: ChaCha20-based CSPRNG for all random generation

## Documentation

- [API Documentation](https://docs.rs/rust-keyvault)
- [Usage Examples](examples/)
- [Security Policy](SECURITY.md) - Threat model, security guarantees, best practices
- [Changelog](CHANGELOG.md) - Version history and release notes

## Testing

Run the test suite:

```bash
# All tests
cargo test --all-features

# Integration tests
cargo test --test '*'

# Benchmarks
cargo bench
```

## Contributing

Contributions are welcome! Please read our security policy in [SECURITY.md](SECURITY.md) before submitting changes.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.