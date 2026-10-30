//! POSIX-local filesystem replay reservation adapter.
//!
//! Reference implementation only. Requires a private, trusted directory on one
//! local filesystem with atomic O_EXCL creation and working fsync semantics.
//! Never use on network shares, replicated volumes or untrusted directories.
//! No authorization, receipt authentication or cryptographic binding is provided.

use crate::replay_contract::{ReplayReservationStore, ReservationError, ReservationOutcome};
use rustix::fs::{open, openat, Mode, OFlags};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAGIC: &[u8] = b"PALACO-HARBOR-REPLAY-1\n";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_BINDING_BYTES: usize = 4096;

// Compiled only into test binaries: deliberate process termination at storage boundaries.
#[cfg(test)]
fn injected_process_termination(stage: &str) {
    if std::env::var("PALACO_HARBOR_TEST_EXIT_STAGE").as_deref() == Ok(stage) {
        std::process::exit(86);
    }
}

/// A single-host reservation store; callers must provision a private directory.
#[derive(Debug)]
pub struct LocalFileReplayStore {
    root: PathBuf,
    directory: File,
}

impl LocalFileReplayStore {
    /// Opens an existing private directory. Does not create or authorize storage.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ReservationError> {
        let root = root.as_ref();
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ReservationError::Unavailable)?;
        let directory = File::from(fd);
        let metadata = directory.metadata().map_err(|_| ReservationError::Unavailable)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ReservationError::Unavailable);
        }
        Ok(Self { root: root.to_path_buf(), directory })
    }

    fn path_for(&self, receipt_id: &str) -> Result<PathBuf, ReservationError> {
        if receipt_id.is_empty() || receipt_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(ReservationError::Unavailable);
        }
        let mut filename = String::from("r-");
        for byte in receipt_id.bytes() {
            use std::fmt::Write as _;
            write!(&mut filename, "{byte:02x}").map_err(|_| ReservationError::Unavailable)?;
        }
        Ok(self.root.join(filename))
    }

    fn encoded(binding_key: &str) -> Result<Vec<u8>, ReservationError> {
        if binding_key.is_empty() || binding_key.len() > MAX_BINDING_BYTES {
            return Err(ReservationError::Unavailable);
        }
        let mut result = Vec::with_capacity(MAGIC.len() + binding_key.len());
        result.extend_from_slice(MAGIC);
        result.extend_from_slice(binding_key.as_bytes());
        Ok(result)
    }

    fn read_existing(
        &self,
        filename: &OsStr,
        expected: &[u8],
    ) -> Result<ReservationOutcome, ReservationError> {
        let fd = openat(
            &self.directory,
            filename,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ReservationError::UncertainCompletion)?;
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|_| ReservationError::UncertainCompletion)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ReservationError::UncertainCompletion);
        }
        let mut bytes = Vec::new();
        file.take((MAGIC.len() + MAX_BINDING_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ReservationError::UncertainCompletion)?;
        if !bytes.starts_with(MAGIC)
            || bytes.len() <= MAGIC.len()
            || bytes.len() > MAGIC.len() + MAX_BINDING_BYTES
        {
            return Err(ReservationError::UncertainCompletion);
        }
        if bytes == expected {
            Ok(ReservationOutcome::AlreadyReserved)
        } else {
            Ok(ReservationOutcome::BindingConflict)
        }
    }

    fn sync_directory(&self) -> Result<(), ReservationError> {
        self.directory
            .sync_all()
            .map_err(|_| ReservationError::UncertainCompletion)
    }
}

impl ReplayReservationStore for LocalFileReplayStore {
    fn reserve(
        &mut self,
        receipt_id: &str,
        binding_key: &str,
    ) -> Result<ReservationOutcome, ReservationError> {
        let path = self.path_for(receipt_id)?;
        let encoded = Self::encoded(binding_key)?;
        let filename = path.file_name().ok_or(ReservationError::Unavailable)?;
        match openat(
            &self.directory,
            filename,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_retain(0o600),
        ) {
            Ok(fd) => {
                let mut file = File::from(fd);
                #[cfg(test)]
                injected_process_termination("after_create");
                // A failure after O_EXCL can leave an incomplete record. Never
                // unlink it automatically: this ID must fail closed on retry.
                file.write_all(&encoded)
                    .map_err(|_| ReservationError::UncertainCompletion)?;
                #[cfg(test)]
                injected_process_termination("after_write");
                file.sync_all()
                    .map_err(|_| ReservationError::UncertainCompletion)?;
                #[cfg(test)]
                injected_process_termination("after_file_sync");
                self.sync_directory()?;
                Ok(ReservationOutcome::Reserved)
            }
            Err(rustix::io::Errno::EXIST) => self.read_existing(filename, &encoded),
            Err(_) => Err(ReservationError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalFileReplayStore, MAGIC};
    use crate::replay_contract::{ReplayReservationStore, ReservationError, ReservationOutcome};
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("palaco-harbor-replay-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap_or_else(|_| panic!("unique test directory"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|_| panic!("secure test permissions"));
            Self(path)
        }

        fn store(&self) -> LocalFileReplayStore {
            LocalFileReplayStore::open(&self.0)
                .unwrap_or_else(|_| panic!("test directory available"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn persists_across_reopen_and_rejects_conflicts() {
        let directory = TestDirectory::new();
        assert_eq!(
            directory.store().reserve("r-1", "binding-a"),
            Ok(ReservationOutcome::Reserved)
        );
        assert_eq!(
            directory.store().reserve("r-1", "binding-a"),
            Ok(ReservationOutcome::AlreadyReserved)
        );
        assert_eq!(
            directory.store().reserve("r-1", "binding-b"),
            Ok(ReservationOutcome::BindingConflict)
        );
    }

    #[test]
    fn competing_instances_exactly_one_wins() {
        let directory = TestDirectory::new();
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = directory.0.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut store = LocalFileReplayStore::open(path).unwrap_or_else(|_| panic!("open"));
                barrier.wait();
                store.reserve("same-receipt", "same-binding")
            }));
        }
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_else(|_| panic!("thread joined")))
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Ok(ReservationOutcome::Reserved))
                .count(),
            1
        );
        assert!(outcomes.iter().all(|outcome| matches!(
            outcome,
            Ok(ReservationOutcome::Reserved | ReservationOutcome::AlreadyReserved)
                | Err(ReservationError::UncertainCompletion)
        )));
    }

    #[test]
    fn interrupted_partial_record_is_never_accepted() {
        let directory = TestDirectory::new();
        let mut store = directory.store();
        let path = store.path_for("partial").unwrap_or_else(|_| panic!("path"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_or_else(|_| panic!("create"));
        file.write_all(&MAGIC[..5])
            .unwrap_or_else(|_| panic!("partial write"));
        file.sync_all().unwrap_or_else(|_| panic!("sync"));
        assert_eq!(
            store.reserve("partial", "binding"),
            Err(ReservationError::UncertainCompletion)
        );
    }

    #[test]
    fn invalid_inputs_fail_closed_without_creating_records() {
        let directory = TestDirectory::new();
        let mut store = directory.store();
        assert_eq!(store.reserve("", "key"), Err(ReservationError::Unavailable));
        assert_eq!(store.reserve("ok", ""), Err(ReservationError::Unavailable));
        assert_eq!(
            store.reserve(&"x".repeat(129), "key"),
            Err(ReservationError::Unavailable)
        );
        assert_eq!(
            fs::read_dir(&directory.0)
                .unwrap_or_else(|_| panic!("list"))
                .count(),
            0
        );
    }
    #[test]
    fn rejects_world_readable_directory() {
        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| panic!("change permissions"));
        assert!(matches!(
            LocalFileReplayStore::open(&directory.0),
            Err(ReservationError::Unavailable)
        ));
    }

    #[test]
    fn rejects_existing_symlink_and_hardlink_records() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new();
        let mut store = directory.store();
        let target = directory.0.join("target");
        fs::write(&target, b"untrusted").unwrap_or_else(|_| panic!("target"));
        let symlink_path = store.path_for("symlink").unwrap_or_else(|_| panic!("path"));
        symlink(&target, &symlink_path).unwrap_or_else(|_| panic!("symlink"));
        assert_eq!(
            store.reserve("symlink", "binding"),
            Err(ReservationError::UncertainCompletion)
        );
        let hardlink_path = store
            .path_for("hardlink")
            .unwrap_or_else(|_| panic!("path"));
        fs::hard_link(&target, &hardlink_path).unwrap_or_else(|_| panic!("hardlink"));
        assert_eq!(
            store.reserve("hardlink", "binding"),
            Err(ReservationError::UncertainCompletion)
        );
    }

    #[test]
    fn termination_child() {
        let Ok(root) = std::env::var("PALACO_HARBOR_TEST_EXIT_ROOT") else {
            return;
        };
        let mut store = LocalFileReplayStore::open(root).unwrap_or_else(|_| panic!("child store"));
        // The test-only hook terminates this process at the requested stage.
        let _ = store.reserve("crash-receipt", "bound-evidence");
        panic!("injected termination was not reached");
    }

    #[test]
    fn terminated_process_cannot_reopen_replay_gate() {
        for (stage, expected) in [
            ("after_create", Err(ReservationError::UncertainCompletion)),
            ("after_write", Ok(ReservationOutcome::AlreadyReserved)),
            ("after_file_sync", Ok(ReservationOutcome::AlreadyReserved)),
        ] {
            let directory = TestDirectory::new();
            let exe = std::env::current_exe().unwrap_or_else(|_| panic!("test binary"));
            let status = Command::new(exe)
                .arg("--exact")
                .arg("local_file_replay::tests::termination_child")
                .env("PALACO_HARBOR_TEST_EXIT_ROOT", &directory.0)
                .env("PALACO_HARBOR_TEST_EXIT_STAGE", stage)
                .status()
                .unwrap_or_else(|_| panic!("run isolated test process"));
            assert_eq!(status.code(), Some(86), "stage: {stage}");
            assert_eq!(
                directory.store().reserve("crash-receipt", "bound-evidence"),
                expected,
                "stage: {stage}"
            );
        }
    }

    #[test]
    fn recovery_after_empty_record_remains_quarantined() {
        let directory = TestDirectory::new();
        let mut store = directory.store();
        let path = store
            .path_for("after-create")
            .unwrap_or_else(|_| panic!("path"));
        File::create(&path).unwrap_or_else(|_| panic!("create interrupted record"));
        assert_eq!(
            store.reserve("after-create", "binding"),
            Err(ReservationError::UncertainCompletion)
        );
        assert_eq!(
            directory.store().reserve("after-create", "binding"),
            Err(ReservationError::UncertainCompletion)
        );
    }
}
