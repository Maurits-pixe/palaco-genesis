//! Deterministic SHA-256 manifest root for public/synthetic offline chunks.
//!
//! Root agreement is integrity-only. Expected roots must be authenticated by
//! an independent trusted mechanism before use.

use sha2::{Digest, Sha256};

/// Maximum entries in a single manifest.
pub const MAX_MANIFEST_ENTRIES: usize = 4_096;
const DOMAIN: &[u8] = b"PALACO-ORCH-036-MANIFEST-V1\0";

/// Manifest entry that contains no private filename or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Stable public identifier, ASCII letters/numbers/hyphen/underscore.
    pub id: String,
    /// Exact claimed chunk size.
    pub bytes: u64,
    /// SHA-256 of the corresponding chunk.
    pub sha256: [u8; 32],
}

/// Explicit manifest verification errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// Empty, unbounded or malformed metadata.
    InvalidEntry,
    /// Entries must be strictly sorted, unique by identifier.
    NotCanonical,
    /// Aggregate size exceeds u64.
    SizeOverflow,
    /// Calculated root differs from the supplied root.
    RootMismatch,
}

/// Compute canonical root of a validated ordered manifest.
///
/// No disk I/O, signing, or network usage takes place.
pub fn manifest_root(entries: &[ManifestEntry]) -> Result<[u8; 32], ManifestError> {
    if entries.is_empty() || entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(ManifestError::InvalidEntry);
    }

    let mut total = 0_u64;
    let mut previous: Option<&str> = None;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update((entries.len() as u32).to_le_bytes());

    for entry in entries {
        if entry.id.is_empty()
            || entry.id.len() > 64
            || entry.bytes == 0
            || !entry
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ManifestError::InvalidEntry);
        }
        if previous.is_some_and(|prev| prev >= entry.id.as_str()) {
            return Err(ManifestError::NotCanonical);
        }
        total = total
            .checked_add(entry.bytes)
            .ok_or(ManifestError::SizeOverflow)?;
        hasher.update([entry.id.len() as u8]);
        hasher.update(entry.id.as_bytes());
        hasher.update(entry.bytes.to_le_bytes());
        hasher.update(entry.sha256);
        previous = Some(&entry.id);
    }

    Ok(hasher.finalize().into())
}

/// Check that a supplied root matches a canonical manifest.
///
/// This cannot establish who supplied the root or whether the chunks exist.
pub fn verify_manifest_root(
    entries: &[ManifestEntry],
    expected: [u8; 32],
) -> Result<(), ManifestError> {
    if manifest_root(entries)? == expected {
        Ok(())
    } else {
        Err(ManifestError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::{manifest_root, verify_manifest_root, ManifestEntry, ManifestError};

    fn entry(id: &str, bytes: u64) -> ManifestEntry {
        ManifestEntry {
            id: id.to_string(),
            bytes,
            sha256: [7_u8; 32],
        }
    }

    #[test]
    fn canonical_root_matches() {
        let items = [entry("a", 1), entry("b", 2)];
        let root = manifest_root(&items);
        assert!(root.is_ok());
        assert_eq!(
            root.and_then(|digest| verify_manifest_root(&items, digest)),
            Ok(())
        );
    }

    #[test]
    fn changed_size_fails_root_check() {
        let original = [entry("a", 1)];
        let altered = [entry("a", 2)];
        let root = manifest_root(&original);
        assert_eq!(
            root.and_then(|digest| verify_manifest_root(&altered, digest)),
            Err(ManifestError::RootMismatch)
        );
    }

    #[test]
    fn changed_chunk_digest_fails_root_check() {
        let original = [entry("a", 1)];
        let mut altered = original.clone();
        altered[0].sha256[0] = 9;
        let root = manifest_root(&original);
        assert_eq!(
            root.and_then(|digest| verify_manifest_root(&altered, digest)),
            Err(ManifestError::RootMismatch)
        );
    }

    #[test]
    fn duplicate_and_reverse_order_are_rejected() {
        assert_eq!(
            manifest_root(&[entry("a", 1), entry("a", 2)]),
            Err(ManifestError::NotCanonical)
        );
        assert_eq!(
            manifest_root(&[entry("b", 1), entry("a", 2)]),
            Err(ManifestError::NotCanonical)
        );
    }

    #[test]
    fn path_like_id_and_empty_list_are_rejected() {
        assert_eq!(manifest_root(&[]), Err(ManifestError::InvalidEntry));
        assert_eq!(
            manifest_root(&[entry("../secret", 1)]),
            Err(ManifestError::InvalidEntry)
        );
    }

    #[test]
    fn aggregate_overflow_is_rejected() {
        assert_eq!(
            manifest_root(&[entry("a", u64::MAX), entry("b", 1)]),
            Err(ManifestError::SizeOverflow)
        );
    }

    #[test]
    fn a_forged_expected_root_cannot_authenticate_provenance() {
        // A matching root is not a signature; an attacker can recompute it.
        let attacker = [entry("forged", 99)];
        let root = manifest_root(&attacker);
        assert_eq!(
            root.and_then(|digest| verify_manifest_root(&attacker, digest)),
            Ok(())
        );
    }
}
