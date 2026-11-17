//! Immutable, locally durable transport for MAC-authenticated audit anchors.
//!
//! This archive is deliberately separate from the ORCHEASTRA snapshot folder.
//! A disk archive is NOT a trusted monotonic authority: the caller must
//! supply independent authenticated generation and verification key custody.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use palaco_runtime::orcheastra::{
    persistence::TrustedRecoveryAnchor,
    recovery::RecoveryCheckpoint,
};
use sha2::{Digest, Sha256};

use super::mac::{MacCheckpoint, MacCheckpointSource, MAC_FORMAT_VERSION};
use super::AnchorError;

const MAGIC: &[u8; 16] = b"PALACO-AUDIT-001";
const MAX_ID: usize = 1024;
static STAGE_ID: AtomicU64 = AtomicU64::new(0);

/// Fail-closed archive transport errors.
#[derive(Debug)]
pub enum ArchiveError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// The archive is malformed, truncated, oversized or has trailing bytes.
    InvalidFormat,
    /// An archived generation is already present.
    AlreadyExists,
    /// Journal identity or generation did not match the requested record.
    ScopeMismatch,
}

fn archive_path(root: &Path, journal_id: &str, generation: u64) -> PathBuf {
    let digest = Sha256::digest(journal_id.as_bytes());
    let name = format!("{digest:x}");
    root.join(name).join(format!("anchor-{generation:020}.bin"))
}

fn encode(record: &MacCheckpoint) -> Result<Vec<u8>, ArchiveError> {
    let journal = record.journal_id.as_bytes();
    let key_id = record.key_id.as_bytes();
    if journal.is_empty()
        || journal.len() > MAX_ID
        || key_id.is_empty()
        || key_id.len() > MAX_ID
        || record.version != MAC_FORMAT_VERSION
    {
        return Err(ArchiveError::InvalidFormat);
    }
    let mut bytes = Vec::with_capacity(16 + 1 + 4 + journal.len() + key_id.len() + 120);
    bytes.extend_from_slice(MAGIC);
    bytes.push(record.version);
    bytes.extend_from_slice(&(journal.len() as u16).to_be_bytes());
    bytes.extend_from_slice(journal);
    bytes.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(&record.anchor.generation.to_be_bytes());
    bytes.extend_from_slice(&record.anchor.checkpoint.plan_hash);
    bytes.extend_from_slice(&record.anchor.checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(&record.anchor.checkpoint.head);
    bytes.extend_from_slice(&record.tag);
    Ok(bytes)
}

/// Persist a complete MAC record without overwriting an existing generation.
///
/// This operation never verifies a MAC and never updates a trusted high-water
/// mark. The caller must invoke an external authoritative publisher and treat
/// unpublished files as orphans.
pub fn archive_record(root: &Path, record: &MacCheckpoint) -> Result<PathBuf, ArchiveError> {
    let bytes = encode(record)?;
    let path = archive_path(root, &record.journal_id, record.anchor.generation);
    let directory = path.parent().ok_or(ArchiveError::InvalidFormat)?;
    fs::create_dir_all(directory).map_err(ArchiveError::Io)?;
    let stage = directory.join(format!(
        ".anchor-{}-{}.tmp",
        std::process::id(),
        STAGE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stage)
        .map_err(ArchiveError::Io)?;
    let result = file.write_all(&bytes).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&stage);
        return Err(ArchiveError::Io(error));
    }
    // Hard-link publication is exclusive, unlike a replacing rename.
    if let Err(error) = fs::hard_link(&stage, &path) {
        let _ = fs::remove_file(&stage);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(ArchiveError::AlreadyExists)
        } else {
            Err(ArchiveError::Io(error))
        };
    }
    fs::remove_file(&stage).map_err(ArchiveError::Io)?;
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(ArchiveError::Io)?;
    Ok(path)
}

fn field<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], ArchiveError> {
    let end = offset.checked_add(len).ok_or(ArchiveError::InvalidFormat)?;
    let part = bytes.get(*offset..end).ok_or(ArchiveError::InvalidFormat)?;
    *offset = end;
    Ok(part)
}

fn number(bytes: &[u8], offset: &mut usize) -> Result<u64, ArchiveError> {
    let raw: [u8; 8] = field(bytes, offset, 8)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat)?;
    Ok(u64::from_be_bytes(raw))
}

fn text_field(bytes: &[u8], offset: &mut usize) -> Result<String, ArchiveError> {
    let size: [u8; 2] = field(bytes, offset, 2)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat)?;
    let size = usize::from(u16::from_be_bytes(size));
    if size == 0 || size > MAX_ID {
        return Err(ArchiveError::InvalidFormat);
    }
    let content = field(bytes, offset, size)?;
    String::from_utf8(content.to_vec()).map_err(|_| ArchiveError::InvalidFormat)
}

/// Reopen and parse exactly one scoped archive generation. Does not trust it.
///
/// The caller must independently verify the returned record's HMAC and the
/// latest externally authenticated generation before using it for recovery.
pub fn read_archived(
    root: &Path,
    journal_id: &str,
    generation: u64,
) -> Result<MacCheckpoint, ArchiveError> {
    if journal_id.is_empty() || journal_id.len() > MAX_ID {
        return Err(ArchiveError::InvalidFormat);
    }
    let path = archive_path(root, journal_id, generation);
    let mut file = File::open(path).map_err(ArchiveError::Io)?;
    // The compact binary format is bounded, including its maximum two IDs.
    let mut bytes = Vec::new();
    file.take(2300)
        .read_to_end(&mut bytes)
        .map_err(ArchiveError::Io)?;
    let mut cursor = 0;
    if field(&bytes, &mut cursor, 16)? != MAGIC
        || field(&bytes, &mut cursor, 1)? != [MAC_FORMAT_VERSION]
    {
        return Err(ArchiveError::InvalidFormat);
    }
    let archived_journal = text_field(&bytes, &mut cursor)?;
    let key_id = text_field(&bytes, &mut cursor)?;
    let observed_generation = number(&bytes, &mut cursor)?;
    let plan_hash = field(&bytes, &mut cursor, 32)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat)?;
    let sequence = number(&bytes, &mut cursor)?;
    let head = field(&bytes, &mut cursor, 32)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat)?;
    let tag = field(&bytes, &mut cursor, 32)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidFormat)?;
    if cursor != bytes.len() {
        return Err(ArchiveError::InvalidFormat);
    }
    if archived_journal != journal_id || observed_generation != generation {
        return Err(ArchiveError::ScopeMismatch);
    }
    Ok(MacCheckpoint {
        version: MAC_FORMAT_VERSION,
        journal_id: archived_journal,
        key_id,
        anchor: TrustedRecoveryAnchor {
            generation,
            checkpoint: RecoveryCheckpoint {
                plan_hash,
                sequence,
                head,
            },
        },
        tag,
    })
}

/// Archive-backed untrusted checkpoint source for the existing MAC verifier.
///
/// `generation_hint` must be supplied from a separate authenticated source;
/// this struct cannot discover which generation is authoritative.
pub struct LocalArchiveSource<'a> {
    /// Root directory dedicated to audit records, not local snapshots.
    pub root: &'a Path,
    /// Externally provided generation hint, not a trust anchor by itself.
    pub generation_hint: u64,
}

impl MacCheckpointSource for LocalArchiveSource<'_> {
    fn checkpoint(&self, journal_id: &str) -> Result<MacCheckpoint, AnchorError> {
        read_archived(self.root, journal_id, self.generation_hint)
            .map_err(|_| AnchorError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orcheastra::mac::{
        authenticate_checkpoint, GenerationAuthority, HmacAnchorVerifier,
    };
    use crate::orcheastra::AuditAnchorVerifier;

    const KEY: [u8; 32] = [0x63; 32];

    struct Generation(u64);
    impl GenerationAuthority for Generation {
        fn latest_generation(&self, _: &str) -> Result<u64, AnchorError> {
            Ok(self.0)
        }
    }

    fn folder() -> PathBuf {
        let id = STAGE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "palaco-audit-archive-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn archive_reopens_and_requires_independent_high_water() -> Result<(), String> {
        let root = folder();
        let anchor = TrustedRecoveryAnchor {
            generation: 4,
            checkpoint: RecoveryCheckpoint {
                plan_hash: [1u8; 32],
                sequence: 2,
                head: [3u8; 32],
            },
        };
        let record = authenticate_checkpoint("orcheastra:test", "key-1", anchor, &KEY);
        archive_record(&root, &record).map_err(|error| format!("{error:?}"))?;
        assert!(matches!(
            archive_record(&root, &record),
            Err(ArchiveError::AlreadyExists)
        ));
        let opened = read_archived(&root, "orcheastra:test", 4)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(opened, record);
        let source = LocalArchiveSource {
            root: &root,
            generation_hint: 4,
        };
        let current = Generation(4);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &current,
            key_id: "key-1",
            key: &KEY,
        };
        assert_eq!(verifier.latest_anchor("orcheastra:test"), Ok(anchor));
        let stale = Generation(5);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &stale,
            key_id: "key-1",
            key: &KEY,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Stale)
        );
        fs::remove_dir_all(root).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    #[test]
    fn tamper_and_wrong_journal_cannot_authenticate() -> Result<(), String> {
        let root = folder();
        let anchor = TrustedRecoveryAnchor {
            generation: 1,
            checkpoint: RecoveryCheckpoint {
                plan_hash: [3u8; 32],
                sequence: 1,
                head: [7u8; 32],
            },
        };
        let record = authenticate_checkpoint("orcheastra:test", "key-1", anchor, &KEY);
        let path = archive_record(&root, &record).map_err(|error| format!("{error:?}"))?;
        let mut raw = fs::read(&path).map_err(|error| format!("{error:?}"))?;
        let last = raw.len().checked_sub(1).ok_or("empty archive")?;
        raw[last] ^= 1;
        fs::write(&path, raw).map_err(|error| format!("{error:?}"))?;
        let source = LocalArchiveSource {
            root: &root,
            generation_hint: 1,
        };
        let generation = Generation(1);
        let verifier = HmacAnchorVerifier {
            source: &source,
            generations: &generation,
            key_id: "key-1",
            key: &KEY,
        };
        assert_eq!(
            verifier.latest_anchor("orcheastra:test"),
            Err(AnchorError::Unauthenticated)
        );
        assert!(read_archived(&root, "other", 1).is_err());
        fs::remove_dir_all(root).map_err(|error| format!("{error:?}"))?;
        Ok(())
    }
}
