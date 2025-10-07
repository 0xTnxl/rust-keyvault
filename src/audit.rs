//! Audit logging for key operations
//!
//! Provides structured logging of security-relevant events for compliance
//! and security monitoring.

use crate::{KeyState, Algorithm};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    /// Key was created
    KeyCreated {
        /// The ID of the created key
        key_id: String,
        /// The algorithm used for the key
        algorithm: Algorithm,
        /// The version number of the key
        version: u32,
    },
    
    /// Key was retrieved/accessed
    KeyAccessed {
        /// The ID of the accessed key
        key_id: String,
        /// The operation performed (e.g., "encrypt", "decrypt", "sign", "verify")
        operation: String,
    },
    
    /// Key was rotated to a new version
    KeyRotated {
        /// The base ID of the key being rotated
        base_id: String,
        /// The version number before rotation
        old_version: u32,
        /// The version number after rotation
        new_version: u32,
    },
    
    /// Key state changed
    KeyStateChanged {
        /// The ID of the key whose state changed
        key_id: String,
        /// The state before the change
        old_state: KeyState,
        /// The state after the change
        new_state: KeyState,
    },
    
    /// Key was deleted
    KeyDeleted {
        /// The ID of the deleted key
        key_id: String,
        /// The version number of the deleted key
        version: u32,
    },
    
    /// Authentication attempt (password-based unlock)
    AuthenticationAttempt {
        /// Whether the authentication was successful
        success: bool,
        /// The storage path being accessed
        storage_path: String,
    },
    
    /// Encryption operation performed
    EncryptionPerformed {
        /// The ID of the key used for encryption
        key_id: String,
        /// The size of data encrypted in bytes
        data_size: usize,
    },
    
    /// Decryption operation performed
    DecryptionPerformed {
        /// The ID of the key used for decryption
        key_id: String,
        /// Whether the decryption was successful
        success: bool,
    },
    
    /// Configuration changed
    ConfigurationChanged {
        /// The name of the configuration setting that changed
        setting: String,
        /// The previous value
        old_value: String,
        /// The new value
        new_value: String,
    },
    
    /// Error occurred
    ErrorOccurred {
        /// The operation that was being performed
        operation: String,
        /// The type of error that occurred
        error_type: String,
        /// Detailed error message
        message: String,
    },
}

/// Audit log entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// When the event occurred
    pub timestamp: SystemTime,
    
    /// The event details
    #[serde(flatten)]
    pub event: AuditEvent,
    
    /// Optional context/metadata
    pub context: Option<String>,
}

impl AuditLogEntry {
    /// Create a new audit log entry
    pub fn new(event: AuditEvent) -> Self {
        Self {
            timestamp: SystemTime::now(),
            event,
            context: None,
        }
    }
    
    /// Add context to the log entry
    pub fn with_context<S: Into<String>>(mut self, context: S) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// Trait for audit logging backends
pub trait AuditLogger: Send + Sync {
    /// Log an audit event
    fn log(&mut self, entry: AuditLogEntry) -> crate::Result<()>;
    
    /// Flush any buffered logs
    fn flush(&mut self) -> crate::Result<()>;
}

/// No-op logger for testing or when auditing is disabled
pub struct NoOpLogger;

impl AuditLogger for NoOpLogger {
    fn log(&mut self, _entry: AuditLogEntry) -> crate::Result<()> {
        Ok(())
    }
    
    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

/// File-based JSON audit logger
pub struct FileAuditLogger {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl FileAuditLogger {
    /// Create a new file-based audit logger
    pub fn new<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        
        let writer = BufWriter::new(file);
        
        Ok(Self { path, writer })
    }
    
    /// Get the path to the audit log file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditLogger for FileAuditLogger {
    fn log(&mut self, entry: AuditLogEntry) -> crate::Result<()> {
        let json = serde_json::to_string(&entry)
            .map_err(|e| crate::Error::storage("audit_logging", &format!("failed to serialize audit entry: {}", e)))?;
        
        writeln!(self.writer, "{}", json)
            .map_err(|e| crate::Error::storage("", &format!("failed to write audit log: {}", e)))?;
        
        Ok(())
    }
    
    fn flush(&mut self) -> crate::Result<()> {
        self.writer.flush()
            .map_err(|e| crate::Error::storage("audit_flush", &format!("failed to flush audit log: {}", e)))
    }
}

impl Drop for FileAuditLogger {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// In-memory audit logger for testing
#[derive(Default)]
pub struct MemoryAuditLogger {
    entries: Vec<AuditLogEntry>,
}

impl MemoryAuditLogger {
    /// Create a new in-memory audit logger
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    
    /// Get all logged entries
    pub fn entries(&self) -> &[AuditLogEntry] {
        &self.entries
    }
    
    /// Clear all logged entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    
    /// Count entries of a specific type
    pub fn count_event_type(&self, predicate: impl Fn(&AuditEvent) -> bool) -> usize {
        self.entries.iter().filter(|e| predicate(&e.event)).count()
    }
}

impl AuditLogger for MemoryAuditLogger {
    fn log(&mut self, entry: AuditLogEntry) -> crate::Result<()> {
        self.entries.push(entry);
        Ok(())
    }
    
    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::KeyCreated {
            key_id: "test-key-123".to_string(),
            algorithm: Algorithm::ChaCha20Poly1305,
            version: 1,
        };
        
        let entry = AuditLogEntry::new(event)
            .with_context("test context");
        
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("KeyCreated"));
        assert!(json.contains("test-key-123"));
        assert!(json.contains("test context"));
    }
    
    #[test]
    fn test_memory_logger() {
        let mut logger = MemoryAuditLogger::new();
        
        let event1 = AuditEvent::KeyCreated {
            key_id: "key1".to_string(),
            algorithm: Algorithm::Aes256Gcm,
            version: 1,
        };
        
        let event2 = AuditEvent::KeyAccessed {
            key_id: "key1".to_string(),
            operation: "encrypt".to_string(),
        };
        
        logger.log(AuditLogEntry::new(event1)).unwrap();
        logger.log(AuditLogEntry::new(event2)).unwrap();
        
        assert_eq!(logger.entries().len(), 2);
        
        let created_count = logger.count_event_type(|e| {
            matches!(e, AuditEvent::KeyCreated { .. })
        });
        assert_eq!(created_count, 1);
    }
    
    #[test]
    fn test_file_logger() {
        use tempfile::tempdir;
        
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        
        let mut logger = FileAuditLogger::new(&log_path).unwrap();
        
        let event = AuditEvent::KeyRotated {
            base_id: "base-123".to_string(),
            old_version: 1,
            new_version: 2,
        };
        
        logger.log(AuditLogEntry::new(event)).unwrap();
        logger.flush().unwrap();
        
        // Verify file was created and contains data
        assert!(log_path.exists());
        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("KeyRotated"));
        assert!(contents.contains("base-123"));
    }
}