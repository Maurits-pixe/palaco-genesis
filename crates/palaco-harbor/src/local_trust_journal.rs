//! Single-host POSIX journal adapter for Harbor trust frames.
//!
//! Requires an existing private directory on a local filesystem with reliable
//! O_EXCL and fsync. File records are NOT authenticated and the filesystem is
//! NOT an independent anti-rollback anchor. Do not use for production trust.

use crate::trust_recovery::{JournalError, TrustFrame, TrustJournal};
use rustix::fs::{open, openat, Mode, OFlags};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAGIC: &str = "PALACO-TRUST-FRAME-v1";
const MAX_BYTES: usize = 65_536;
const MAX_KEYS: usize = 256;

#[cfg(test)]
fn termination_at(stage: &str) {
    if std::env::var("PALACO_TRUST_TEST_EXIT_STAGE").as_deref() == Ok(stage) {
        std::process::exit(86);
    }
}

/// Descriptor-relative immutable frame files, one per sequence number.
#[derive(Debug)]
pub struct LocalTrustJournal {
    root: PathBuf,
    directory: File,
}

impl LocalTrustJournal {
    /// Opens a pre-provisioned private local directory without creating it.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, JournalError> {
        let root = root.as_ref();
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| JournalError::Unavailable)?;
        let directory = File::from(fd);
        let meta = directory
            .metadata()
            .map_err(|_| JournalError::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(JournalError::Unavailable);
        }
        Ok(Self {
            root: root.to_path_buf(),
            directory,
        })
    }

    fn name(seq: u64) -> String {
        format!("trust-{seq:020}.frame")
    }

    fn key_valid(key: &str) -> bool {
        !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    }

    fn encode(frame: &TrustFrame) -> Result<Vec<u8>, JournalError> {
        if frame.sequence == 0
            || frame.trust_epoch == 0
            || frame.highest_trusted_time_ms == 0
            || frame.revoked_keys.len() > MAX_KEYS
            || frame.revoked_keys.iter().any(|key| !Self::key_valid(key))
        {
            return Err(JournalError::Corrupt);
        }
        let mut body = format!(
            "{MAGIC}\n{}\n{}\n{}\n{}\n",
            frame.sequence,
            frame.trust_epoch,
            frame.highest_trusted_time_ms,
            frame.revoked_keys.len()
        );
        for key in &frame.revoked_keys {
            body.push_str(key);
            body.push('\n');
        }
        if body.len() > MAX_BYTES {
            return Err(JournalError::Corrupt);
        }
        Ok(body.into_bytes())
    }

    fn decode(bytes: &[u8]) -> Result<TrustFrame, JournalError> {
        let body = std::str::from_utf8(bytes).map_err(|_| JournalError::Corrupt)?;
        if !body.ends_with('\n') || body.len() > MAX_BYTES {
            return Err(JournalError::Corrupt);
        }
        let mut lines = body.lines();
        if lines.next() != Some(MAGIC) {
            return Err(JournalError::Corrupt);
        }
        let parse_number = |line: Option<&str>| -> Result<u64, JournalError> {
            let value = line.ok_or(JournalError::Corrupt)?;
            if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
                return Err(JournalError::Corrupt);
            }
            value.parse::<u64>().map_err(|_| JournalError::Corrupt)
        };
        let sequence = parse_number(lines.next())?;
        let trust_epoch = parse_number(lines.next())?;
        let highest_trusted_time_ms = parse_number(lines.next())?;
        let count = parse_number(lines.next())?;
        if sequence == 0
            || trust_epoch == 0
            || highest_trusted_time_ms == 0
            || count > MAX_KEYS as u64
        {
            return Err(JournalError::Corrupt);
        }
        let mut revoked_keys = BTreeSet::new();
        for _ in 0..count {
            let key = lines.next().ok_or(JournalError::Corrupt)?;
            if !Self::key_valid(key) || !revoked_keys.insert(key.to_owned()) {
                return Err(JournalError::Corrupt);
            }
        }
        if lines.next().is_some() {
            return Err(JournalError::Corrupt);
        }
        let frame = TrustFrame {
            sequence,
            trust_epoch,
            highest_trusted_time_ms,
            revoked_keys,
        };
        if Self::encode(&frame)?.as_slice() != bytes {
            return Err(JournalError::Corrupt);
        }
        Ok(frame)
    }

    fn read_frame(&self, name: &str, expected_sequence: u64) -> Result<TrustFrame, JournalError> {
        let fd = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| JournalError::Corrupt)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(|_| JournalError::Corrupt)?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_BYTES as u64 {
            return Err(JournalError::Corrupt);
        }
        let mut bytes = Vec::new();
        file.take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| JournalError::Corrupt)?;
        let frame = Self::decode(&bytes)?;
        if frame.sequence != expected_sequence {
            return Err(JournalError::Corrupt);
        }
        Ok(frame)
    }
}

impl TrustJournal for LocalTrustJournal {
    fn load(&self) -> Result<Vec<TrustFrame>, JournalError> {
        let mut seqs = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| JournalError::Unavailable)? {
            let entry = entry.map_err(|_| JournalError::Corrupt)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(JournalError::Corrupt)?;
            if name.starts_with("trust-") {
                let middle = name
                    .strip_prefix("trust-")
                    .and_then(|text| text.strip_suffix(".frame"))
                    .ok_or(JournalError::Corrupt)?;
                if middle.len() != 20 || !middle.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(JournalError::Corrupt);
                }
                seqs.push(middle.parse::<u64>().map_err(|_| JournalError::Corrupt)?);
            }
        }
        seqs.sort_unstable();
        if seqs.len() > 10_000 {
            return Err(JournalError::Corrupt);
        }
        let mut frames = Vec::with_capacity(seqs.len());
        for (index, sequence) in seqs.into_iter().enumerate() {
            if sequence != (index as u64) + 1 {
                return Err(JournalError::Corrupt);
            }
            frames.push(self.read_frame(&Self::name(sequence), sequence)?);
        }
        Ok(frames)
    }

    fn append_sync(&mut self, frame: &TrustFrame) -> Result<(), JournalError> {
        let bytes = Self::encode(frame)?;
        // The caller must load/recover first; O_EXCL prevents a competing writer
        // from silently replacing a frame with the same sequence.
        let fd = openat(
            &self.directory,
            Self::name(frame.sequence),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_retain(0o600),
        )
        .map_err(|_| JournalError::UncertainCompletion)?;
        let mut file = File::from(fd);
        #[cfg(test)]
        termination_at("after_create");
        file.write_all(&bytes)
            .map_err(|_| JournalError::UncertainCompletion)?;
        #[cfg(test)]
        termination_at("after_write");
        file.sync_all()
            .map_err(|_| JournalError::UncertainCompletion)?;
        #[cfg(test)]
        termination_at("after_file_sync");
        self.directory
            .sync_all()
            .map_err(|_| JournalError::UncertainCompletion)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalTrustJournal, MAGIC};
    use crate::trust_recovery::{
        persist_transition, recover, JournalError, RecoveryError, RecoveryFloor, TrustFrame,
        TrustJournal, TrustTransition,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("palaco-trust-journal-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap_or_else(|_| panic!("create unique test directory"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|_| panic!("set private permissions"));
            Self(path)
        }

        fn open(&self) -> LocalTrustJournal {
            LocalTrustJournal::open(&self.0).unwrap_or_else(|_| panic!("open private journal"))
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn genesis() -> TrustFrame {
        TrustFrame {
            sequence: 1,
            trust_epoch: 5,
            highest_trusted_time_ms: 100,
            revoked_keys: BTreeSet::new(),
        }
    }

    fn floor() -> RecoveryFloor {
        RecoveryFloor {
            minimum_sequence: 1,
            minimum_trust_epoch: 5,
            minimum_trusted_time_ms: 100,
        }
    }

    #[test]
    fn actual_files_survive_reopen_and_replay() {
        let dir = TestDir::new();
        dir.open()
            .append_sync(&genesis())
            .unwrap_or_else(|_| panic!("write genesis"));
        let state = persist_transition(
            &mut dir.open(),
            floor(),
            TrustTransition::Revoke("key-7".to_owned()),
        );
        assert!(state.is_ok());
        let recovered = recover(&dir.open(), floor());
        assert!(matches!(recovered, Ok(ref f) if f.revoked_keys.contains("key-7")));
    }

    #[test]
    fn partial_and_duplicate_files_fail_closed() {
        let dir = TestDir::new();
        fs::write(dir.0.join(LocalTrustJournal::name(1)), MAGIC.as_bytes())
            .unwrap_or_else(|_| panic!("write partial"));
        assert_eq!(
            recover(&dir.open(), floor()),
            Err(RecoveryError::Journal(JournalError::Corrupt))
        );
        assert_eq!(
            dir.open().append_sync(&genesis()),
            Err(JournalError::UncertainCompletion)
        );
    }

    #[test]
    fn missing_middle_frame_and_symlink_fail_closed() {
        let dir = TestDir::new();
        dir.open()
            .append_sync(&genesis())
            .unwrap_or_else(|_| panic!("genesis"));
        let mut third = genesis();
        third.sequence = 3;
        dir.open()
            .append_sync(&third)
            .unwrap_or_else(|_| panic!("third"));
        assert_eq!(dir.open().load(), Err(JournalError::Corrupt));

        let dir = TestDir::new();
        std::os::unix::fs::symlink("/dev/null", dir.0.join(LocalTrustJournal::name(1)))
            .unwrap_or_else(|_| panic!("symlink"));
        assert_eq!(dir.open().load(), Err(JournalError::Corrupt));
    }

    #[test]
    fn rejects_world_readable_directory() {
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| panic!("make public"));
        assert!(matches!(
            LocalTrustJournal::open(&dir.0),
            Err(JournalError::Unavailable)
        ));
    }

    #[test]
    fn process_termination_child() {
        let Ok(root) = std::env::var("PALACO_TRUST_TEST_EXIT_ROOT") else {
            return;
        };
        let mut store = LocalTrustJournal::open(root).unwrap_or_else(|_| panic!("child open"));
        let _ = store.append_sync(&genesis());
        panic!("termination hook not reached");
    }

    #[test]
    fn terminated_process_never_replays_incomplete_frame() {
        for stage in ["after_create", "after_write", "after_file_sync"] {
            let dir = TestDir::new();
            let status = Command::new(std::env::current_exe().unwrap_or_else(|_| panic!("exe")))
                .arg("--exact")
                .arg("local_trust_journal::tests::process_termination_child")
                .env("PALACO_TRUST_TEST_EXIT_ROOT", &dir.0)
                .env("PALACO_TRUST_TEST_EXIT_STAGE", stage)
                .status()
                .unwrap_or_else(|_| panic!("run child"));
            assert_eq!(status.code(), Some(86));
            let result = recover(&dir.open(), floor());
            if stage == "after_create" {
                assert_eq!(result, Err(RecoveryError::Journal(JournalError::Corrupt)));
            } else {
                assert_eq!(result, Ok(genesis()));
            }
        }
    }
}
