//! Deterministic SHA-256 integrity chain for ORCHEASTRA decisions.
//!
//! Local verification detects accidental or adversarial mutation of the
//! supplied records relative to the supplied head, but authenticity,
//! durability, and rollback detection require an externally trusted anchor.

use sha2::{Digest, Sha256};

use super::tasks::DecisionEntry;
use super::{AdmissionDecision, AdmissionReason};

/// One SHA-256 digest represented as 32 bytes.
pub type Digest256 = [u8; 32];

/// Chain record bound to its predecessor and a decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainedDecision {
    /// Decision record being committed to the chain.
    pub entry: DecisionEntry,
    /// Hash of the previous record, or zero bytes for the first.
    pub previous_hash: Digest256,
    /// SHA-256 over the domain-separated canonical record encoding.
    pub hash: Digest256,
}

/// Structural or cryptographic integrity verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// Entry sequence is discontinuous or did not start at one.
    InvalidSequence,
    /// Previous hash does not match the preceding record.
    BrokenLink,
    /// Record bytes do not match their recorded digest.
    DigestMismatch,
    /// Expected externally anchored head differs from the calculated head.
    HeadMismatch,
    /// The input record list cannot fit the sequence counter.
    SequenceOverflow,
}

/// Returns a SHA-256 chain for a canonical decision journal.
///
/// `entries` must have sequence numbers starting at 1 and increasing
/// by one. This function performs no writes and no authorization.
pub fn chain_entries(entries: &[DecisionEntry]) -> Result<Vec<ChainedDecision>, ChainError> {
    let mut records = Vec::with_capacity(entries.len());
    let mut previous_hash = [0u8; 32];

    for (index, entry) in entries.iter().enumerate() {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ChainError::SequenceOverflow)?;
        if entry.sequence != expected {
            return Err(ChainError::InvalidSequence);
        }
        let hash = record_digest(entry, &previous_hash);
        records.push(ChainedDecision {
            entry: entry.clone(),
            previous_hash,
            hash,
        });
        previous_hash = hash;
    }
    Ok(records)
}

/// Verify sequence, chaining and integrity against an externally recorded head.
///
/// `expected_head` must come from a trusted independent source for rollback
/// or truncation detection. A forged chain with its own forged head cannot be
/// authenticated by hashes alone.
pub fn verify_chain(
    records: &[ChainedDecision],
    expected_head: &Digest256,
) -> Result<(), ChainError> {
    let mut previous_hash = [0u8; 32];
    for (index, record) in records.iter().enumerate() {
        let expected = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ChainError::SequenceOverflow)?;
        if record.entry.sequence != expected {
            return Err(ChainError::InvalidSequence);
        }
        if record.previous_hash != previous_hash {
            return Err(ChainError::BrokenLink);
        }
        if record.hash != record_digest(&record.entry, &previous_hash) {
            return Err(ChainError::DigestMismatch);
        }
        previous_hash = record.hash;
    }
    if previous_hash != *expected_head {
        return Err(ChainError::HeadMismatch);
    }
    Ok(())
}

/// Return the head of a chain (all zeroes for an empty chain).
#[must_use]
pub fn chain_head(records: &[ChainedDecision]) -> Digest256 {
    records.last().map_or([0u8; 32], |last| last.hash)
}

fn push_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn reason_code(reason: AdmissionReason) -> u8 {
    match reason {
        AdmissionReason::Admitted => 0,
        AdmissionReason::ReadOnly => 1,
        AdmissionReason::IdentityMissing => 2,
        AdmissionReason::AuthorityMissing => 3,
        AdmissionReason::EvidenceMissing => 4,
        AdmissionReason::ScopeMismatch => 5,
        AdmissionReason::StaleContext => 6,
        AdmissionReason::Revoked => 7,
        AdmissionReason::Hold => 8,
        AdmissionReason::CitadelDenied => 9,
    }
}

fn record_digest(entry: &DecisionEntry, previous_hash: &Digest256) -> Digest256 {
    let mut hash = Sha256::new();
    hash.update(b"PALACO-ORCHEASTRA-DECISION-CHAIN-V1");
    hash.update(previous_hash);
    hash.update(entry.sequence.to_be_bytes());
    push_bytes(&mut hash, entry.task_id.as_bytes());
    match entry.decision {
        AdmissionDecision::ObserveOnly => hash.update([0u8, 0]),
        AdmissionDecision::Proposed => hash.update([1u8, 0]),
        AdmissionDecision::Blocked(reason) => hash.update([2u8, reason_code(reason)]),
    }
    push_bytes(&mut hash, entry.evidence_ref.as_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sequence: u64, task: &str, decision: AdmissionDecision) -> DecisionEntry {
        DecisionEntry {
            sequence,
            task_id: task.to_owned(),
            decision,
            evidence_ref: format!("evidence:{task}"),
        }
    }

    #[test]
    fn deterministic_chain_and_anchor_verify() -> Result<(), ChainError> {
        let entries = [
            entry(1, "identity", AdmissionDecision::ObserveOnly),
            entry(2, "rio", AdmissionDecision::Blocked(AdmissionReason::Hold)),
        ];
        let first = chain_entries(&entries)?;
        let second = chain_entries(&entries)?;
        assert_eq!(first, second);
        assert_eq!(verify_chain(&first, &chain_head(&first)), Ok(()));
        Ok(())
    }

    #[test]
    fn tampering_is_detected() -> Result<(), ChainError> {
        let original = chain_entries(&[
            entry(1, "a", AdmissionDecision::Proposed),
            entry(2, "b", AdmissionDecision::Proposed),
        ])?;
        let anchor = chain_head(&original);
        let mut tampered = original.clone();
        tampered[0].entry.evidence_ref = "counterfeit".to_owned();
        assert_eq!(
            verify_chain(&tampered, &anchor),
            Err(ChainError::DigestMismatch)
        );
        tampered = original.clone();
        tampered[1].previous_hash = [9u8; 32];
        assert_eq!(
            verify_chain(&tampered, &anchor),
            Err(ChainError::BrokenLink)
        );
        Ok(())
    }

    #[test]
    fn missing_or_reordered_record_is_rejected() -> Result<(), ChainError> {
        let first = entry(1, "a", AdmissionDecision::ObserveOnly);
        let second = entry(2, "b", AdmissionDecision::Proposed);
        assert_eq!(
            chain_entries(&[second.clone(), first]),
            Err(ChainError::InvalidSequence)
        );
        let chain = chain_entries(&[entry(1, "a", AdmissionDecision::ObserveOnly), second])?;
        assert_eq!(
            verify_chain(&chain[..1], &chain_head(&chain)),
            Err(ChainError::HeadMismatch)
        );
        Ok(())
    }

    #[test]
    fn empty_chain_only_matches_zero_head() {
        assert_eq!(verify_chain(&[], &[0u8; 32]), Ok(()));
        assert_eq!(verify_chain(&[], &[1u8; 32]), Err(ChainError::HeadMismatch));
    }
}
