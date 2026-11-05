//! Create-only review policy records checked against an independently retained pin.
//!
//! A local record never supplies its own trusted pin. This module does not
//! implement a hardware counter or authenticate the provisioning of a pin.

use crate::offline_anchor_signature::{
    verify_anchor, AnchorReviewError, AnchorReviewPolicy, SignatureCheckedAnchor,
    SignedCheckpointAnchor,
};
use crate::offline_ed25519::Ed25519ReviewVerifier;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"PLPOL001";
const FRAME_BYTES: usize = 128;

/// Pin proposal or externally provisioned expectation, never self-authenticating.
///
/// The caller must retain the current pin outside rollback-prone policy storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPin {
    /// Exact immutable record version, not a request to scan for latest.
    pub version: u64,
    /// Domain-separated commitment over version, registry, key and both floors.
    pub digest: [u8; 32],
}

/// Any policy failure prevents this review path from selecting a verifier.
#[derive(Debug)]
pub enum PolicyStoreError {
    /// No independent expectation was supplied.
    MissingPin,
    /// Malformed frame, policy or version.
    Invalid,
    /// Stored record differs from the independent expectation.
    PinMismatch,
    /// A proposed update decreases a floor or changes registry/key.
    InvalidAdvance,
    /// Version exists, including an incomplete write.
    AlreadyExists,
    /// Filesystem failure; a failed write can leave preserved evidence.
    Io(std::io::Error),
    /// Signature evidence did not satisfy the reopened policy.
    Anchor(AnchorReviewError),
}

/// Bind exact policy fields to a record version; this is only a pin proposal.
#[must_use]
pub fn policy_pin(version: u64, policy: &AnchorReviewPolicy) -> PolicyPin {
    let mut hasher = Sha256::new();
    hasher.update(b"PALACO-ORCH-057-POLICY-RECORD-v1");
    hasher.update(version.to_be_bytes());
    hasher.update(policy.registry_id);
    hasher.update(policy.pinned_public_key);
    hasher.update(policy.minimum_revision.to_be_bytes());
    hasher.update(policy.minimum_policy_epoch.to_be_bytes());
    PolicyPin {
        version,
        digest: hasher.finalize().into(),
    }
}

/// Stage public policy bytes without overwrite and sync file and directory.
///
/// Returns a proposed pin, never adoption or authorization. This low-level staging
/// API does not decide whether a policy is current. An independent actor must
/// validate and retain a pin separately before relying on it after restart.
pub fn stage_policy_record(
    root: &Path,
    version: u64,
    policy: &AnchorReviewPolicy,
) -> Result<PolicyPin, PolicyStoreError> {
    validate_root(root)?;
    validate_policy(version, policy)?;
    let pin = policy_pin(version, policy);
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&version.to_be_bytes());
    frame.extend_from_slice(&policy.registry_id);
    frame.extend_from_slice(&policy.pinned_public_key);
    frame.extend_from_slice(&policy.minimum_revision.to_be_bytes());
    frame.extend_from_slice(&policy.minimum_policy_epoch.to_be_bytes());
    frame.extend_from_slice(&pin.digest);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(record_path(root, version))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PolicyStoreError::AlreadyExists
            } else {
                PolicyStoreError::Io(error)
            }
        })?;
    file.write_all(&frame).map_err(PolicyStoreError::Io)?;
    file.sync_all().map_err(PolicyStoreError::Io)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(PolicyStoreError::Io)?;
    Ok(pin)
}

/// Read exactly the independently pinned version and verify its complete policy.
///
/// Missing/corrupt/mismatched records never fall back to an older file.
/// Local filenames, checksums and directory ordering cannot create a trusted pin.
pub fn read_pinned_policy(
    root: &Path,
    pin: Option<&PolicyPin>,
) -> Result<AnchorReviewPolicy, PolicyStoreError> {
    let pin = pin.ok_or(PolicyStoreError::MissingPin)?;
    if pin.version == 0 {
        return Err(PolicyStoreError::Invalid);
    }
    validate_root(root)?;
    let path = record_path(root, pin.version);
    let metadata = fs::symlink_metadata(&path).map_err(PolicyStoreError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() != FRAME_BYTES as u64 {
        return Err(PolicyStoreError::Invalid);
    }
    let mut frame = Vec::new();
    File::open(path)
        .map_err(PolicyStoreError::Io)?
        .take((FRAME_BYTES + 1) as u64)
        .read_to_end(&mut frame)
        .map_err(PolicyStoreError::Io)?;
    if frame.len() != FRAME_BYTES || &frame[..8] != MAGIC {
        return Err(PolicyStoreError::Invalid);
    }
    let invalid = |_| PolicyStoreError::Invalid;
    let version = u64::from_be_bytes(frame[8..16].try_into().map_err(invalid)?);
    let policy = AnchorReviewPolicy {
        registry_id: frame[16..48].try_into().map_err(invalid)?,
        pinned_public_key: frame[48..80].try_into().map_err(invalid)?,
        minimum_revision: u64::from_be_bytes(frame[80..88].try_into().map_err(invalid)?),
        minimum_policy_epoch: u64::from_be_bytes(frame[88..96].try_into().map_err(invalid)?),
    };
    validate_policy(version, &policy)?;
    let calculated = policy_pin(version, &policy);
    if calculated != *pin || frame[96..128] != calculated.digest {
        return Err(PolicyStoreError::PinMismatch);
    }
    Ok(policy)
}

/// Stage the next version with nondecreasing floors and unchanged registry/key.
///
/// Does not adopt the proposed pin. A separate atomic pin update is required.
/// Concurrent proposals use create-only storage; only one can occupy a version.
pub fn stage_policy_advance(
    root: &Path,
    current: &PolicyPin,
    next: &AnchorReviewPolicy,
) -> Result<PolicyPin, PolicyStoreError> {
    let previous = read_pinned_policy(root, Some(current))?;
    if next.registry_id != previous.registry_id
        || next.pinned_public_key != previous.pinned_public_key
        || next.minimum_revision < previous.minimum_revision
        || next.minimum_policy_epoch < previous.minimum_policy_epoch
    {
        return Err(PolicyStoreError::InvalidAdvance);
    }
    let version = current
        .version
        .checked_add(1)
        .ok_or(PolicyStoreError::InvalidAdvance)?;
    stage_policy_record(root, version, next)
}

/// Reopen pinned policy before checking externally supplied signed evidence.
///
/// No fallback policy, floor update, recovery approval or execution is performed.
pub fn verify_with_pinned_policy(
    root: &Path,
    pin: Option<&PolicyPin>,
    receipt: &SignedCheckpointAnchor,
) -> Result<SignatureCheckedAnchor, PolicyStoreError> {
    let policy = read_pinned_policy(root, pin)?;
    verify_anchor(receipt, &policy).map_err(PolicyStoreError::Anchor)
}

fn validate_policy(version: u64, policy: &AnchorReviewPolicy) -> Result<(), PolicyStoreError> {
    if version == 0
        || policy.registry_id == [0; 32]
        || Ed25519ReviewVerifier::from_public_key(&policy.pinned_public_key).is_none()
    {
        return Err(PolicyStoreError::Invalid);
    }
    Ok(())
}

fn validate_root(root: &Path) -> Result<(), PolicyStoreError> {
    if !fs::symlink_metadata(root)
        .map_err(PolicyStoreError::Io)?
        .file_type()
        .is_dir()
    {
        return Err(PolicyStoreError::Invalid);
    }
    Ok(())
}

fn record_path(root: &Path, version: u64) -> PathBuf {
    root.join(format!("policy_{version}.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_anchor_signature::anchor_signing_digest;
    use crate::offline_revocation_checkpoint::RevocationCheckpoint;
    use ed25519_dalek::{Signer, SigningKey};

    fn policy() -> AnchorReviewPolicy {
        AnchorReviewPolicy {
            registry_id: [7; 32],
            pinned_public_key: SigningKey::from_bytes(&[57; 32]).verifying_key().to_bytes(),
            minimum_revision: 4,
            minimum_policy_epoch: 2,
        }
    }

    fn root() -> Result<PathBuf, std::io::Error> {
        let root = std::env::temp_dir().join(format!("palaco-orch057-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root)?;
        Ok(root)
    }

    #[test]
    fn reopen_requires_independent_exact_pin() -> Result<(), std::io::Error> {
        let root = root()?;
        let policy = policy();
        assert!(stage_policy_record(&root, 1, &policy).is_ok());
        assert!(matches!(
            read_pinned_policy(&root, None),
            Err(PolicyStoreError::MissingPin)
        ));
        assert!(matches!(
            read_pinned_policy(&root, Some(&policy_pin(1, &policy))),
            Ok(value) if value == policy
        ));
        assert!(matches!(
            stage_policy_record(&root, 1, &policy),
            Err(PolicyStoreError::AlreadyExists)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn advance_rejects_lower_floors_or_identity_changes() -> Result<(), std::io::Error> {
        let root = root()?;
        let original = policy();
        assert!(stage_policy_record(&root, 1, &original).is_ok());
        let current = policy_pin(1, &original);
        for field in 0..4 {
            let mut next = original;
            match field {
                0 => next.minimum_revision -= 1,
                1 => next.minimum_policy_epoch -= 1,
                2 => next.registry_id = [9; 32],
                _ => next.pinned_public_key = [0; 32],
            }
            assert!(matches!(
                stage_policy_advance(&root, &current, &next),
                Err(PolicyStoreError::InvalidAdvance)
            ));
        }
        assert!(!record_path(&root, 2).exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn restored_self_consistent_old_policy_fails_current_pin() -> Result<(), std::io::Error> {
        let root = root()?;
        let old = policy();
        let mut latest = old;
        latest.minimum_revision = 5;
        let current_pin = policy_pin(2, &latest);
        // An attacker can stage valid checksummed old fields under a new filename.
        assert!(stage_policy_record(&root, 2, &old).is_ok());
        assert!(matches!(
            read_pinned_policy(&root, Some(&current_pin)),
            Err(PolicyStoreError::PinMismatch)
        ));
        // If the independent pin is also restored, protection is lost.
        assert!(read_pinned_policy(&root, Some(&policy_pin(2, &old))).is_ok());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_current_record_never_falls_back() -> Result<(), std::io::Error> {
        let root = root()?;
        let old = policy();
        assert!(stage_policy_record(&root, 1, &old).is_ok());
        assert!(matches!(
            read_pinned_policy(&root, Some(&policy_pin(2, &old))),
            Err(PolicyStoreError::Io(_))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn interrupted_and_oversized_records_are_retained_and_denied() -> Result<(), std::io::Error> {
        let root = root()?;
        let policy = policy();
        let path = record_path(&root, 1);
        fs::write(&path, b"partial")?;
        assert!(read_pinned_policy(&root, Some(&policy_pin(1, &policy))).is_err());
        assert!(matches!(
            stage_policy_record(&root, 1, &policy),
            Err(PolicyStoreError::AlreadyExists)
        ));
        assert_eq!(fs::read(&path)?, b"partial");
        fs::write(path, [0; FRAME_BYTES + 1])?;
        assert!(read_pinned_policy(&root, Some(&policy_pin(1, &policy))).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn reopened_floor_rejects_previously_valid_signed_anchor() -> Result<(), std::io::Error> {
        let root = root()?;
        let original = policy();
        let signer = SigningKey::from_bytes(&[57; 32]);
        let mut receipt = SignedCheckpointAnchor {
            registry_id: original.registry_id,
            checkpoint: RevocationCheckpoint::new(4, 2, [8; 32]),
            signer_key_id: Sha256::digest(original.pinned_public_key).into(),
            signature: [0; 64],
        };
        receipt.signature = signer.sign(&anchor_signing_digest(&receipt)).to_bytes();
        assert!(stage_policy_record(&root, 1, &original).is_ok());
        let pin = policy_pin(1, &original);
        assert!(verify_with_pinned_policy(&root, Some(&pin), &receipt).is_ok());
        let mut next = original;
        next.minimum_revision = 5;
        assert!(stage_policy_advance(&root, &pin, &next).is_ok());
        let next_pin = policy_pin(2, &next);
        assert!(matches!(
            verify_with_pinned_policy(&root, Some(&next_pin), &receipt),
            Err(PolicyStoreError::Anchor(AnchorReviewError::BelowFloor))
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_record_is_denied() -> Result<(), std::io::Error> {
        let root = root()?;
        let policy = policy();
        assert!(stage_policy_record(&root, 1, &policy).is_ok());
        fs::rename(record_path(&root, 1), root.join("target"))?;
        std::os::unix::fs::symlink(root.join("target"), record_path(&root, 1))?;
        assert!(matches!(
            read_pinned_policy(&root, Some(&policy_pin(1, &policy))),
            Err(PolicyStoreError::Invalid)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[ignore = "explicitly invoked fresh-process policy reader"]
    fn policy_restart_child() -> Result<(), std::io::Error> {
        let root = std::env::var_os("PALACO_POLICY_RESTART_ROOT")
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("missing fixture root"))?;
        let mut expected = policy();
        expected.minimum_revision = 5;
        assert!(matches!(
            read_pinned_policy(&root, Some(&policy_pin(2, &expected))),
            Ok(value) if value == expected
        ));
        Ok(())
    }

    struct RestartChild(std::process::Child);

    impl Drop for RestartChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn advanced_policy_reopens_in_a_fresh_process() -> Result<(), std::io::Error> {
        let root = root()?;
        let original = policy();
        assert!(stage_policy_record(&root, 1, &original).is_ok());
        let mut next = original;
        next.minimum_revision = 5;
        assert!(stage_policy_advance(&root, &policy_pin(1, &original), &next).is_ok());
        let mut child = RestartChild(
            std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "offline_policy_store::tests::policy_restart_child",
                    "--ignored",
                ])
                .env("PALACO_POLICY_RESTART_ROOT", &root)
                .spawn()?,
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait()? {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::other("policy restart timeout"));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
