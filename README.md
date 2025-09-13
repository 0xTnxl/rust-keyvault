# rust-keyvault

[![Crates.io](https://img.shields.io/crates/v/rust-keyvault.svg)](https://crates.io/crates/rust-keyvault)
[![Documentation](https://docs.rs/rust-keyvault/badge.svg)](https://docs.rs/rust-keyvault)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/yourusername/rust-keyvault#license)

A secure, modern cryptographic key management library for Rust.

## `rust-keyvault` features

- **AEAD Encryption**: ChaCha20-Poly1305 and AES-256-GCM
- **Key Rotation**: Automatic versioning and lifecycle management
- **Encrypted Storage**: File-based persistence with Argon2 key derivation
- **Thread-Safe**: Multi-threaded storage backends
- **Memory Protection**: Automatic zeroization of sensitive data
- **Zero Unsafe**: `#![forbid(unsafe_code)]` - completely memory safe

## Quick Start

Add to your `Cargo.toml`;

```toml
[dependencies]
rust-keyvault = "0.1"
```

### Basic Usage

```rust
use rust_keyvault::*;
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

## Architecture

```
┌─────────────────┐
│  Applications   │
└─────────────────┘
         │
┌─────────────────┐    ┌──────────────────┐
│   KeyStore      │    │  EncryptedStore  │
│   Traits        │    │  Traits          │
└─────────────────┘    └──────────────────┘
         │                       │
┌─────────────────┐    ┌──────────────────┐
│   MemoryStore   │    │    FileStore     │
│   (Testing)     │    │  (Production)    │
└─────────────────┘    └──────────────────┘
         │                       │
┌─────────────────┐    ┌──────────────────┐
│  AEAD Crypto    │    │  Argon2 KDF      │
│  ChaCha20/AES   │    │  Key Derivation  │
└─────────────────┘    └──────────────────┘
```

## Security Features

- **Modern Cryptography**: ChaCha20-Poly1305 and AES-256-GCM AEAD
- **Memory Safety**: Automatic zeroization with `zeroize` crate
- **Key Derivation**: Argon2id password-based key derivation
- **Authenticated Encryption**: Built-in integrity protection
- **Secure Random**: ChaCha20-based CSPRNG

## Documentation

- [API Documentation](https://docs.rs/rust-keyvault)
- [Usage Examples](examples/)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.