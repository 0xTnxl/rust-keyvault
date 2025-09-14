# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-XX

### Added

#### Core Features
- **KeyStore trait** - Abstract interface for key storage backends
- **MemoryStore** - Thread-safe in-memory key storage for testing
- **FileStore** - Encrypted file-based persistent storage
- **Key lifecycle management** - Active, Deprecated, Revoked, Rotating states

#### Cryptographic Features  
- **AEAD encryption** - ChaCha20-Poly1305 and AES-256-GCM support
- **Key generation** - Cryptographically secure random key generation
- **Argon2 key derivation** - Password-based master key derivation
- **Memory protection** - Automatic zeroization of sensitive data

#### Key Management
- **Key rotation** - Automatic versioning with backward compatibility
- **Metadata tracking** - Creation time, expiration, algorithm binding
- **Base ID system** - Track key families across rotations
- **Version cleanup** - Policy-based old version removal

#### Storage Features
- **Encryption at rest** - Master key encryption for file storage
- **Serialization** - JSON-based key persistence with encryption
- **Thread safety** - `Send + Sync` support for concurrent access
- **Error handling** - Comprehensive typed error system

#### Security Features
- **Memory safety** - `#![forbid(unsafe_code)]` - zero unsafe code
- **Constant-time operations** - Side-channel resistant comparisons
- **Secure random** - ChaCha20-based CSPRNG
- **Algorithm binding** - Keys tied to specific algorithms

### Security Considerations

- Uses industry-standard cryptographic primitives
- Implements proper key lifecycle management
- Provides secure defaults for all operations
- Automatic memory zeroization prevents key material leaks
- Argon2id protects against password-based attacks

### Dependencies

- `aead` - AEAD encryption trait definitions
- `chacha20poly1305` - ChaCha20-Poly1305 AEAD implementation  
- `aes-gcm` - AES-256-GCM AEAD implementation
- `argon2` - Argon2 password hashing
- `zeroize` - Secure memory clearing
- `serde` - Serialization framework
- `thiserror` - Error handling

### Breaking Changes

None - this is the initial release.

### Documentation

- Complete API documentation with examples
- Usage guide with practical examples
- Security considerations and best practices

### Testing

- Comprehensive unit tests for all components
- Integration tests for storage backends
- Security tests for encryption and key rotation
- Cross-platform compatibility testing

---

## [Unreleased]

### Planned Features
- HSM integration (PKCS#11)
- Cloud KMS support (AWS, Azure, GCP)
- Key derivation functions (HKDF)
- Audit logging
- Distributed key management
- Performance optimizations