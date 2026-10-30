//! Private POSIX append-only cache of signed anchor floors.
//!
//! Signed records detect tampering, not complete filesystem snapshot rollback.
//! A separately governed durable external high-water checkpoint is required.
//! Never treat this single-host adapter as production authorization.

use crate::anchor_cas::{AnchorRecord, StoreError};
use crate::remote_anchor_adapter::{attestation_bytes, AttestedAnchor};
use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{open, openat, Mode, OFlags};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: usize = 64_000;
const PREFIX: &[u8] = b"PALACO-HARBOR-REMOTE-ANCHOR-v1\0";
const MAX_FRAMES: usize = 10_000;

#[cfg(test)]
fn terminate_at(stage: &str) {
    if std::env::var("PALACO_ANCHOR_TEST_EXIT_STAGE").as_deref() == Ok(stage) {
        std::process::exit(86);
    }
}

#[derive(Debug)]
pub struct LocalAnchorFloorJournal {
    root: PathBuf,
    directory: File,
    verifying_key: [u8; 32],
}

impl LocalAnchorFloorJournal {
    pub fn open(root: impl AsRef<Path>, verifying_key: [u8; 32]) -> Result<Self, StoreError> {
        let root = root.as_ref();
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::Unavailable)?;
        let directory = File::from(fd);
        let meta = directory.metadata().map_err(|_| StoreError::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::Unavailable);
        }
        VerifyingKey::from_bytes(&verifying_key).map_err(|_| StoreError::IntegrityUncertain)?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
            verifying_key,
        })
    }

    fn filename(revision: u64) -> String {
        format!("anchor-{revision:020}.frame")
    }

    fn take_number(bytes: &[u8], cursor: &mut usize) -> Result<u64, StoreError> {
        let end = cursor
            .checked_add(8)
            .ok_or(StoreError::IntegrityUncertain)?;
        let value: [u8; 8] = bytes
            .get(*cursor..end)
            .ok_or(StoreError::IntegrityUncertain)?
            .try_into()
            .map_err(|_| StoreError::IntegrityUncertain)?;
        *cursor = end;
        Ok(u64::from_be_bytes(value))
    }

    fn take_id(bytes: &[u8], cursor: &mut usize) -> Result<String, StoreError> {
        let len = usize::try_from(Self::take_number(bytes, cursor)?)
            .map_err(|_| StoreError::IntegrityUncertain)?;
        if len == 0 || len > 128 {
            return Err(StoreError::IntegrityUncertain);
        }
        let end = cursor
            .checked_add(len)
            .ok_or(StoreError::IntegrityUncertain)?;
        let value = std::str::from_utf8(
            bytes
                .get(*cursor..end)
                .ok_or(StoreError::IntegrityUncertain)?,
        )
        .map_err(|_| StoreError::IntegrityUncertain)?;
        *cursor = end;
        Ok(value.to_owned())
    }

    fn decode(&self, bytes: &[u8]) -> Result<AnchorRecord, StoreError> {
        if bytes.len() > MAX_RECORD_BYTES
            || bytes.len() < PREFIX.len() + 64
            || !bytes.starts_with(PREFIX)
        {
            return Err(StoreError::IntegrityUncertain);
        }
        let split = bytes.len() - 64;
        let message = &bytes[..split];
        let signature: [u8; 64] = bytes[split..]
            .try_into()
            .map_err(|_| StoreError::IntegrityUncertain)?;
        let verifying = VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| StoreError::IntegrityUncertain)?;
        verifying
            .verify_strict(message, &Signature::from_bytes(&signature))
            .map_err(|_| StoreError::IntegrityUncertain)?;
        let mut cursor = PREFIX.len();
        let revision = Self::take_number(message, &mut cursor)?;
        let signer_epoch = Self::take_number(message, &mut cursor)?;
        let sequence = Self::take_number(message, &mut cursor)?;
        let digest_end = cursor
            .checked_add(32)
            .ok_or(StoreError::IntegrityUncertain)?;
        let chain_digest = message
            .get(cursor..digest_end)
            .ok_or(StoreError::IntegrityUncertain)?
            .try_into()
            .map_err(|_| StoreError::IntegrityUncertain)?;
        cursor = digest_end;
        let signer_id = Self::take_id(message, &mut cursor)?;
        let count = Self::take_number(message, &mut cursor)?;
        if count > 256 {
            return Err(StoreError::IntegrityUncertain);
        }
        let mut retired_signers = BTreeSet::new();
        for _ in 0..count {
            if !retired_signers.insert(Self::take_id(message, &mut cursor)?) {
                return Err(StoreError::IntegrityUncertain);
            }
        }
        let record = AnchorRecord {
            revision,
            signer_epoch,
            sequence,
            chain_digest,
            signer_id,
            retired_signers,
        };
        if cursor != split || attestation_bytes(&record)?.as_slice() != message {
            return Err(StoreError::IntegrityUncertain);
        }
        Ok(record)
    }

    /// Reload the highest complete signed anchor; never skip a damaged frame.
    pub fn recover(
        &self,
        external_floor: Option<&AnchorRecord>,
    ) -> Result<Option<AnchorRecord>, StoreError> {
        let mut revisions = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| StoreError::Unavailable)? {
            let entry = entry.map_err(|_| StoreError::IntegrityUncertain)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(StoreError::IntegrityUncertain)?;
            if let Some(part) = name.strip_prefix("anchor-") {
                let part = part
                    .strip_suffix(".frame")
                    .ok_or(StoreError::IntegrityUncertain)?;
                if part.len() != 20 || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(StoreError::IntegrityUncertain);
                }
                revisions.push(
                    part.parse::<u64>()
                        .map_err(|_| StoreError::IntegrityUncertain)?,
                );
            }
        }
        if revisions.len() > MAX_FRAMES {
            return Err(StoreError::IntegrityUncertain);
        }
        revisions.sort_unstable();
        let mut latest: Option<AnchorRecord> = None;
        for revision in revisions {
            if latest
                .as_ref()
                .is_some_and(|p| p.revision.checked_add(1) != Some(revision))
            {
                return Err(StoreError::IntegrityUncertain);
            }
            let fd = openat(
                &self.directory,
                Self::filename(revision),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| StoreError::IntegrityUncertain)?;
            let file = File::from(fd);
            let meta = file
                .metadata()
                .map_err(|_| StoreError::IntegrityUncertain)?;
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_RECORD_BYTES as u64 {
                return Err(StoreError::IntegrityUncertain);
            }
            let mut bytes = Vec::new();
            file.take((MAX_RECORD_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| StoreError::IntegrityUncertain)?;
            let record = self.decode(&bytes)?;
            if record.revision != revision {
                return Err(StoreError::IntegrityUncertain);
            }
            if let Some(prior) = &latest {
                if record.signer_epoch < prior.signer_epoch
                    || record.sequence < prior.sequence
                    || !prior.retired_signers.is_subset(&record.retired_signers)
                    || (record.signer_id != prior.signer_id
                        && (!record.retired_signers.contains(&prior.signer_id)
                            || record.signer_epoch <= prior.signer_epoch))
                {
                    return Err(StoreError::IntegrityUncertain);
                }
            }
            latest = Some(record);
        }
        if let Some(floor) = external_floor {
            // An empty or rolled-back directory must never silently reset state.
            let current = latest.as_ref().ok_or(StoreError::IntegrityUncertain)?;
            if current.revision < floor.revision
                || (current.revision == floor.revision && current != floor)
                || current.signer_epoch < floor.signer_epoch
                || current.sequence < floor.sequence
                || !floor.retired_signers.is_subset(&current.retired_signers)
            {
                return Err(StoreError::IntegrityUncertain);
            }
        }
        Ok(latest)
    }

    /// Persist an already independently authenticated signed anchor.
    /// Caller must serialize writers and reload after uncertain completion.
    pub fn append_sync(&mut self, anchor: &AttestedAnchor) -> Result<(), StoreError> {
        let bytes = attestation_bytes(&anchor.record)?;
        let mut frame = bytes;
        frame.extend_from_slice(&anchor.signature);
        if frame.len() > MAX_RECORD_BYTES {
            return Err(StoreError::IntegrityUncertain);
        }
        let verified = self.decode(&frame)?;
        if let Some(previous) = self.recover(None)? {
            if previous.revision.checked_add(1) != Some(verified.revision)
                || verified.signer_epoch < previous.signer_epoch
                || verified.sequence < previous.sequence
                || !previous
                    .retired_signers
                    .is_subset(&verified.retired_signers)
                || (verified.signer_id != previous.signer_id
                    && (!verified.retired_signers.contains(&previous.signer_id)
                        || verified.signer_epoch <= previous.signer_epoch))
            {
                return Err(StoreError::IntegrityUncertain);
            }
        }
        let fd = openat(
            &self.directory,
            Self::filename(verified.revision),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_retain(0o600),
        )
        .map_err(|_| StoreError::UncertainCompletion)?;
        let mut file = File::from(fd);
        #[cfg(test)]
        terminate_at("after_create");
        #[cfg(test)]
        if std::env::var("PALACO_ANCHOR_TEST_IO_FAULT").as_deref() == Ok("partial_write") {
            file.write_all(&frame[..frame.len() / 2])
                .map_err(|_| StoreError::UncertainCompletion)?;
            return Err(StoreError::UncertainCompletion);
        }
        file.write_all(&frame)
            .map_err(|_| StoreError::UncertainCompletion)?;
        #[cfg(test)]
        terminate_at("after_write");
        #[cfg(test)]
        if std::env::var("PALACO_ANCHOR_TEST_IO_FAULT").as_deref() == Ok("file_sync_failure") {
            return Err(StoreError::UncertainCompletion);
        }
        file.sync_all()
            .map_err(|_| StoreError::UncertainCompletion)?;
        #[cfg(test)]
        terminate_at("after_file_sync");
        #[cfg(test)]
        if std::env::var("PALACO_ANCHOR_TEST_DIRSYNC_FAILURE").as_deref() == Ok("1") {
            return Err(StoreError::UncertainCompletion);
        }
        self.directory
            .sync_all()
            .map_err(|_| StoreError::UncertainCompletion)?;
        #[cfg(test)]
        terminate_at("after_directory_sync");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LocalAnchorFloorJournal;
    use crate::anchor_cas::{AnchorRecord, StoreError};
    use crate::remote_anchor_adapter::{attestation_bytes, AttestedAnchor};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("palaco-anchor-floor-{}-{id}", std::process::id()));
            fs::create_dir(&root).unwrap_or_else(|_| panic!("create"));
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|_| panic!("permissions"));
            Self(root)
        }
        fn open(&self, key: &SigningKey) -> LocalAnchorFloorJournal {
            LocalAnchorFloorJournal::open(&self.0, key.verifying_key().to_bytes())
                .unwrap_or_else(|_| panic!("open"))
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn record(revision: u64) -> AnchorRecord {
        AnchorRecord {
            revision,
            signer_epoch: 5,
            sequence: revision,
            chain_digest: [revision as u8; 32],
            signer_id: "signer-a".to_owned(),
            retired_signers: BTreeSet::new(),
        }
    }
    fn signed(record: AnchorRecord, key: &SigningKey) -> AttestedAnchor {
        let bytes = attestation_bytes(&record).unwrap_or_else(|_| panic!("encode"));
        AttestedAnchor {
            record,
            signature: key.sign(&bytes).to_bytes(),
        }
    }
    #[test]
    fn signed_floor_survives_reopen_and_detects_external_rollback() {
        let dir = TestDir::new();
        let key = SigningKey::from_bytes(&[49; 32]);
        dir.open(&key)
            .append_sync(&signed(record(1), &key))
            .unwrap_or_else(|_| panic!("append"));
        dir.open(&key)
            .append_sync(&signed(record(2), &key))
            .unwrap_or_else(|_| panic!("append"));
        assert_eq!(dir.open(&key).recover(None), Ok(Some(record(2))));
        assert_eq!(
            dir.open(&key).recover(Some(&record(3))),
            Err(StoreError::IntegrityUncertain)
        );
        fs::remove_file(dir.0.join(LocalAnchorFloorJournal::filename(2)))
            .unwrap_or_else(|_| panic!("truncate simulated snapshot"));
        assert_eq!(
            dir.open(&key).recover(Some(&record(2))),
            Err(StoreError::IntegrityUncertain)
        );
    }
    #[test]
    fn partial_and_tampered_files_fail_closed() {
        let dir = TestDir::new();
        let key = SigningKey::from_bytes(&[49; 32]);
        let mut journal = dir.open(&key);
        journal
            .append_sync(&signed(record(1), &key))
            .unwrap_or_else(|_| panic!("append"));
        assert_eq!(
            journal.append_sync(&signed(record(1), &key)),
            Err(StoreError::IntegrityUncertain)
        );
        let path = dir.0.join(LocalAnchorFloorJournal::filename(1));
        fs::write(&path, b"partial").unwrap_or_else(|_| panic!("corrupt"));
        assert_eq!(
            dir.open(&key).recover(None),
            Err(StoreError::IntegrityUncertain)
        );
    }
    #[test]
    fn gap_and_wrong_signing_key_fail_closed() {
        let dir = TestDir::new();
        let key = SigningKey::from_bytes(&[49; 32]);
        dir.open(&key)
            .append_sync(&signed(record(1), &key))
            .unwrap_or_else(|_| panic!("append"));
        let mut third = signed(record(3), &key);
        let bytes = attestation_bytes(&third.record).unwrap_or_else(|_| panic!("encode"));
        third.signature = key.sign(&bytes).to_bytes();
        assert_eq!(
            dir.open(&key).append_sync(&third),
            Err(StoreError::IntegrityUncertain)
        );
        let other = SigningKey::from_bytes(&[50; 32]);
        assert_eq!(
            dir.open(&other).recover(None),
            Err(StoreError::IntegrityUncertain)
        );
    }
    #[test]
    fn process_termination_child() {
        let Ok(root) = std::env::var("PALACO_ANCHOR_TEST_EXIT_ROOT") else {
            return;
        };
        let key = SigningKey::from_bytes(&[49; 32]);
        let mut journal = LocalAnchorFloorJournal::open(root, key.verifying_key().to_bytes())
            .unwrap_or_else(|_| panic!("child open"));
        let _ = journal.append_sync(&signed(record(1), &key));
        panic!("termination hook not reached");
    }

    #[test]
    fn terminated_process_never_silently_skips_partial_anchor() {
        for stage in [
            "after_create",
            "after_write",
            "after_file_sync",
            "after_directory_sync",
        ] {
            let dir = TestDir::new();
            let status = Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("exe")))
                .arg("--exact")
                .arg("local_anchor_floor_journal::tests::process_termination_child")
                .env("PALACO_ANCHOR_TEST_EXIT_ROOT", &dir.0)
                .env("PALACO_ANCHOR_TEST_EXIT_STAGE", stage)
                .status()
                .unwrap_or_else(|_| panic!("child"));
            assert_eq!(status.code(), Some(86));
            let key = SigningKey::from_bytes(&[49; 32]);
            let recovered = dir.open(&key).recover(None);
            if stage == "after_create" {
                assert_eq!(recovered, Err(StoreError::IntegrityUncertain));
            } else {
                // This is process termination, not a power-loss durability test.
                assert_eq!(recovered, Ok(Some(record(1))));
            }
        }
    }

    #[test]
    fn directory_sync_failure_is_uncertain_and_requires_reconciliation() {
        let dir = TestDir::new();
        let status = Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("exe")))
            .arg("--exact")
            .arg("local_anchor_floor_journal::tests::directory_sync_failure_child")
            .env("PALACO_ANCHOR_TEST_DIRSYNC_ROOT", &dir.0)
            .env("PALACO_ANCHOR_TEST_DIRSYNC_FAILURE", "1")
            .status()
            .unwrap_or_else(|_| panic!("child"));
        assert!(status.success());
        let key = SigningKey::from_bytes(&[49; 32]);
        // Process-visible recovery is not evidence of persistence across power loss.
        assert_eq!(dir.open(&key).recover(None), Ok(Some(record(1))));
        assert_eq!(
            dir.open(&key).append_sync(&signed(record(1), &key)),
            Err(StoreError::IntegrityUncertain)
        );
        assert_eq!(
            dir.open(&key).recover(Some(&record(2))),
            Err(StoreError::IntegrityUncertain)
        );
    }

    #[test]
    fn directory_sync_failure_child() {
        let Ok(root) = std::env::var("PALACO_ANCHOR_TEST_DIRSYNC_ROOT") else {
            return;
        };
        let key = SigningKey::from_bytes(&[49; 32]);
        let mut journal = LocalAnchorFloorJournal::open(root, key.verifying_key().to_bytes())
            .unwrap_or_else(|_| panic!("child open"));
        assert_eq!(
            journal.append_sync(&signed(record(1), &key)),
            Err(StoreError::UncertainCompletion)
        );
    }

    #[test]
    fn io_fault_child() {
        let Ok(root) = std::env::var("PALACO_ANCHOR_TEST_IO_ROOT") else {
            return;
        };
        let key = SigningKey::from_bytes(&[49; 32]);
        let mut journal = LocalAnchorFloorJournal::open(root, key.verifying_key().to_bytes())
            .unwrap_or_else(|_| panic!("child open"));
        assert_eq!(
            journal.append_sync(&signed(record(1), &key)),
            Err(StoreError::UncertainCompletion)
        );
    }

    #[test]
    fn partial_write_remains_poisoned_across_reopen() {
        let dir = TestDir::new();
        let status = Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("exe")))
            .arg("--exact")
            .arg("local_anchor_floor_journal::tests::io_fault_child")
            .env("PALACO_ANCHOR_TEST_IO_ROOT", &dir.0)
            .env("PALACO_ANCHOR_TEST_IO_FAULT", "partial_write")
            .status()
            .unwrap_or_else(|_| panic!("child"));
        assert!(status.success());
        let key = SigningKey::from_bytes(&[49; 32]);
        let mut journal = dir.open(&key);
        assert_eq!(journal.recover(None), Err(StoreError::IntegrityUncertain));
        assert_eq!(
            journal.append_sync(&signed(record(1), &key)),
            Err(StoreError::IntegrityUncertain)
        );
    }

    #[test]
    fn failed_file_sync_does_not_prove_durability() {
        let dir = TestDir::new();
        let status = Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("exe")))
            .arg("--exact")
            .arg("local_anchor_floor_journal::tests::io_fault_child")
            .env("PALACO_ANCHOR_TEST_IO_ROOT", &dir.0)
            .env("PALACO_ANCHOR_TEST_IO_FAULT", "file_sync_failure")
            .status()
            .unwrap_or_else(|_| panic!("child"));
        assert!(status.success());
        let key = SigningKey::from_bytes(&[49; 32]);
        // Visible bytes are not proof of persistence through a power cut.
        assert_eq!(dir.open(&key).recover(None), Ok(Some(record(1))));
        assert_eq!(
            dir.open(&key).recover(Some(&record(2))),
            Err(StoreError::IntegrityUncertain)
        );
        assert_eq!(
            dir.open(&key).append_sync(&signed(record(1), &key)),
            Err(StoreError::IntegrityUncertain)
        );
    }

    #[test]
    fn symlink_and_hardlink_frames_are_rejected_on_recovery() {
        let key = SigningKey::from_bytes(&[49; 32]);
        for link_type in ["symlink", "hardlink"] {
            let dir = TestDir::new();
            let frame = dir.0.join(LocalAnchorFloorJournal::filename(1));
            dir.open(&key)
                .append_sync(&signed(record(1), &key))
                .unwrap_or_else(|_| panic!("append"));
            let target = dir.0.join("saved-frame");
            fs::rename(&frame, &target).unwrap_or_else(|_| panic!("rename"));
            if link_type == "symlink" {
                symlink(&target, &frame).unwrap_or_else(|_| panic!("symlink"));
            } else {
                fs::hard_link(&target, &frame).unwrap_or_else(|_| panic!("hardlink"));
            }
            assert_eq!(
                dir.open(&key).recover(None),
                Err(StoreError::IntegrityUncertain)
            );
        }
    }

    #[test]
    fn malformed_anchor_names_cannot_be_ignored() {
        let key = SigningKey::from_bytes(&[49; 32]);
        for name in [
            "anchor-1.frame",
            "anchor-00000000000000000001.backup",
            "anchor-0000000000000000000x.frame",
        ] {
            let dir = TestDir::new();
            dir.open(&key)
                .append_sync(&signed(record(1), &key))
                .unwrap_or_else(|_| panic!("append"));
            fs::write(dir.0.join(name), b"untrusted").unwrap_or_else(|_| panic!("write malformed"));
            assert_eq!(
                dir.open(&key).recover(None),
                Err(StoreError::IntegrityUncertain)
            );
        }
    }

    #[test]
    fn permissive_directory_and_oversized_frame_fail_closed() {
        let key = SigningKey::from_bytes(&[49; 32]);
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777))
            .unwrap_or_else(|_| panic!("permissions"));
        assert!(matches!(
            LocalAnchorFloorJournal::open(&dir.0, key.verifying_key().to_bytes()),
            Err(StoreError::Unavailable)
        ));
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("permissions"));
        fs::write(
            dir.0.join(LocalAnchorFloorJournal::filename(1)),
            vec![0_u8; 64_001],
        )
        .unwrap_or_else(|_| panic!("oversized frame"));
        assert_eq!(
            dir.open(&key).recover(None),
            Err(StoreError::IntegrityUncertain)
        );
    }

    #[test]
    fn interrupted_first_write_cannot_be_reused_as_fresh_genesis() {
        let dir = TestDir::new();
        let key = SigningKey::from_bytes(&[49; 32]);
        fs::write(dir.0.join(LocalAnchorFloorJournal::filename(1)), [])
            .unwrap_or_else(|_| panic!("create empty partial"));
        let mut journal = dir.open(&key);
        assert_eq!(journal.recover(None), Err(StoreError::IntegrityUncertain));
        assert_eq!(
            journal.append_sync(&signed(record(1), &key)),
            Err(StoreError::IntegrityUncertain)
        );
        assert_eq!(
            journal.recover(Some(&record(1))),
            Err(StoreError::IntegrityUncertain)
        );
    }
}
