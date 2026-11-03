//! Non-sensitive local draft store prototype for ORCHEASTRA.
//!
//! Files are integrity-checked, but NOT encrypted or authenticated.
//! Never use this prototype for credentials, personal data, or production drafts.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const MAGIC: &[u8] = b"PALACO-DRAFT-1\n";
const MAX_DRAFT_BYTES: usize = 1024 * 1024;
const DIGEST_BYTES: usize = 32;
const LENGTH_BYTES: usize = 8;

/// Stores a previously absent non-sensitive draft in an actor-specific folder.
///
/// Each identifier is restricted to ASCII letters, digits, dash and underscore.
/// A previously used identifier is never overwritten; a partial crash artifact
/// remains detectable on the next read. The caller must supply a trusted root
/// directory and restrict filesystem access independently.
pub fn store_new_draft(
    root: &Path,
    actor_id: &str,
    draft_id: &str,
    payload: &[u8],
) -> io::Result<()> {
    validate_identifier(actor_id)?;
    validate_identifier(draft_id)?;
    if payload.len() > MAX_DRAFT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "draft too large",
        ));
    }

    let actor_dir = root.join(actor_id);
    fs::create_dir_all(&actor_dir)?;
    reject_symlink(&actor_dir)?;

    let path = actor_dir.join(format!("{draft_id}.draft"));
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let digest = Sha256::digest(payload);
    file.write_all(MAGIC)?;
    file.write_all(&(payload.len() as u64).to_be_bytes())?;
    file.write_all(&digest)?;
    file.write_all(payload)?;
    file.sync_all()?;
    Ok(())
}

/// Reads a local draft only if its header, size and SHA-256 digest agree.
///
/// SHA-256 detects accidental corruption, but is not an authenticity proof.
/// An attacker who can replace the file can also replace its unkeyed digest.
pub fn load_draft(root: &Path, actor_id: &str, draft_id: &str) -> io::Result<Vec<u8>> {
    validate_identifier(actor_id)?;
    validate_identifier(draft_id)?;
    let actor_dir = root.join(actor_id);
    reject_symlink(&actor_dir)?;
    let path = actor_dir.join(format!("{draft_id}.draft"));
    reject_symlink(&path)?;

    let file = OpenOptions::new().read(true).open(path)?;
    let mut encoded = Vec::new();
    file.take((MAGIC.len() + LENGTH_BYTES + DIGEST_BYTES + MAX_DRAFT_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    let header_len = MAGIC.len() + LENGTH_BYTES + DIGEST_BYTES;
    if encoded.len() < header_len || !encoded.starts_with(MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid draft header",
        ));
    }
    let length_end = MAGIC.len() + LENGTH_BYTES;
    let length_bytes: [u8; LENGTH_BYTES] = encoded[MAGIC.len()..length_end]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid draft length"))?;
    let expected_len = usize::try_from(u64::from_be_bytes(length_bytes))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "draft length overflow"))?;
    let payload = &encoded[header_len..];
    if expected_len > MAX_DRAFT_BYTES || payload.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "draft length mismatch",
        ));
    }
    let expected_digest = &encoded[length_end..header_len];
    let actual_digest = Sha256::digest(payload);
    if actual_digest[..] != expected_digest[..] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "draft digest mismatch",
        ));
    }
    Ok(payload.to_vec())
}

fn validate_identifier(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid draft identifier",
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symbolic link forbidden",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_draft, store_new_draft};
    use std::{fs, io, path::PathBuf};

    fn temporary_root() -> PathBuf {
        std::env::temp_dir().join(format!("palaco-draft-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn non_sensitive_draft_survives_reopen() -> io::Result<()> {
        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"synthetic fixture")?;
        assert_eq!(
            load_draft(&root, "actor_1", "draft_1")?,
            b"synthetic fixture"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn duplicate_create_is_rejected() -> io::Result<()> {
        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"fixture")?;
        assert!(store_new_draft(&root, "actor_1", "draft_1", b"changed").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn traversal_identifier_is_rejected() {
        let root = temporary_root();
        assert!(store_new_draft(&root, "../other", "draft", b"fixture").is_err());
        assert!(load_draft(&root, "actor", "../../other").is_err());
    }

    #[test]
    fn corrupted_draft_is_rejected() -> io::Result<()> {
        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"fixture")?;
        let path = root.join("actor_1").join("draft_1.draft");
        let mut encoded = fs::read(&path)?;
        if let Some(last) = encoded.last_mut() {
            *last ^= 0x01;
        }
        fs::write(path, encoded)?;
        assert!(load_draft(&root, "actor_1", "draft_1").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn truncated_draft_is_rejected() -> io::Result<()> {
        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"fixture")?;
        let path = root.join("actor_1").join("draft_1.draft");
        let file = fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(10)?;
        assert!(load_draft(&root, "actor_1", "draft_1").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn oversized_draft_is_rejected_before_write() {
        let root = temporary_root();
        let oversized = vec![0u8; 1024 * 1024 + 1];
        assert!(store_new_draft(&root, "actor_1", "draft_1", &oversized).is_err());
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_draft_is_rejected() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"fixture")?;
        let actor_dir = root.join("actor_1");
        symlink(actor_dir.join("draft_1.draft"), actor_dir.join("linked.draft"))?;
        assert!(load_draft(&root, "actor_1", "linked").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn actor_namespaces_are_separate() -> io::Result<()> {
        let root = temporary_root();
        store_new_draft(&root, "actor_1", "draft_1", b"fixture")?;
        assert!(load_draft(&root, "actor_2", "draft_1").is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
