//! Remote anchor transport boundary with signed response validation.
//!
//! No production network client or independent anchor service is instantiated.
//! Transport must provide authenticated TLS, true atomic CAS, durable quorum,
//! and rollback-resistant freshness. A caller-supplied response signer is not
//! automatically an authorized governance root. Never grants admission.

use crate::anchor_cas::{AnchorRecord, AtomicAnchorStore, StoreError, SwapOutcome};
use ed25519_dalek::{Signature, VerifyingKey};

const DOMAIN: &[u8] = b"PALACO-HARBOR-REMOTE-ANCHOR-v1\0";
const MAX_RETIRED: usize = 256;

/// A signed remote response, explicitly bound to the complete anchor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedAnchor {
    pub record: AnchorRecord,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    Timeout,
    InvalidResponse,
}

/// Conditional remote commit must attest the *resulting* state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSwap {
    Applied(AttestedAnchor),
    PreconditionFailed,
}

/// The transport is a contract, not a provided HTTP implementation.
pub trait RemoteAnchorTransport {
    fn read(&self) -> Result<AttestedAnchor, TransportError>;
    fn compare_and_swap(
        &mut self,
        expected: &AnchorRecord,
        next: &AnchorRecord,
    ) -> Result<RemoteSwap, TransportError>;
}

/// Holds a caller-provisioned pinned response-verification key.
pub struct RemoteAnchorAdapter<T> {
    transport: T,
    response_public_key: [u8; 32],
}

impl<T> RemoteAnchorAdapter<T> {
    pub fn new(transport: T, response_public_key: [u8; 32]) -> Self {
        Self {
            transport,
            response_public_key,
        }
    }
}

/// Deterministic message encoding for a remote attested full anchor state.
pub fn attestation_bytes(record: &AnchorRecord) -> Result<Vec<u8>, StoreError> {
    if record.revision == 0
        || record.signer_epoch == 0
        || record.sequence == 0
        || record.signer_id.is_empty()
        || record.signer_id.len() > 128
        || record.retired_signers.len() > MAX_RETIRED
        || record
            .retired_signers
            .iter()
            .any(|id| id.is_empty() || id.len() > 128)
    {
        return Err(StoreError::IntegrityUncertain);
    }
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&record.revision.to_be_bytes());
    bytes.extend_from_slice(&record.signer_epoch.to_be_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.extend_from_slice(&record.chain_digest);
    let id_len =
        u64::try_from(record.signer_id.len()).map_err(|_| StoreError::IntegrityUncertain)?;
    bytes.extend_from_slice(&id_len.to_be_bytes());
    bytes.extend_from_slice(record.signer_id.as_bytes());
    let count =
        u64::try_from(record.retired_signers.len()).map_err(|_| StoreError::IntegrityUncertain)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for id in &record.retired_signers {
        let len = u64::try_from(id.len()).map_err(|_| StoreError::IntegrityUncertain)?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(id.as_bytes());
    }
    Ok(bytes)
}

impl<T: RemoteAnchorTransport> RemoteAnchorAdapter<T> {
    fn checked(&self, attested: AttestedAnchor) -> Result<AnchorRecord, StoreError> {
        let verifying = VerifyingKey::from_bytes(&self.response_public_key)
            .map_err(|_| StoreError::IntegrityUncertain)?;
        let message = attestation_bytes(&attested.record)?;
        verifying
            .verify_strict(&message, &Signature::from_bytes(&attested.signature))
            .map_err(|_| StoreError::IntegrityUncertain)?;
        Ok(attested.record)
    }

    fn map_transport(error: TransportError) -> StoreError {
        match error {
            TransportError::Unavailable => StoreError::Unavailable,
            TransportError::Timeout => StoreError::UncertainCompletion,
            TransportError::InvalidResponse => StoreError::IntegrityUncertain,
        }
    }
}

impl<T: RemoteAnchorTransport> AtomicAnchorStore for RemoteAnchorAdapter<T> {
    fn load(&self) -> Result<AnchorRecord, StoreError> {
        let response = self.transport.read().map_err(Self::map_transport)?;
        self.checked(response)
    }

    fn compare_and_swap(
        &mut self,
        expected: &AnchorRecord,
        next: &AnchorRecord,
    ) -> Result<SwapOutcome, StoreError> {
        let response = self
            .transport
            .compare_and_swap(expected, next)
            .map_err(Self::map_transport)?;
        match response {
            RemoteSwap::PreconditionFailed => Ok(SwapOutcome::Conflict),
            RemoteSwap::Applied(attested) => {
                let returned = self.checked(attested)?;
                if returned != *next {
                    return Err(StoreError::IntegrityUncertain);
                }
                Ok(SwapOutcome::Committed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attestation_bytes, AttestedAnchor, RemoteAnchorAdapter, RemoteAnchorTransport, RemoteSwap,
        TransportError,
    };
    use crate::anchor_cas::{AnchorRecord, AtomicAnchorStore, StoreError, SwapOutcome};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    struct ScriptedRemote {
        current: AnchorRecord,
        fail_read: Option<TransportError>,
        fail_write: Option<TransportError>,
        conflict: bool,
        tamper_ack: bool,
        signer: SigningKey,
    }

    fn record() -> AnchorRecord {
        AnchorRecord {
            revision: 1,
            signer_epoch: 5,
            sequence: 1,
            chain_digest: [1; 32],
            signer_id: "signer-a".to_owned(),
            retired_signers: BTreeSet::new(),
        }
    }

    fn signed(record: AnchorRecord, signer: &SigningKey) -> AttestedAnchor {
        let message = attestation_bytes(&record).unwrap_or_else(|_| panic!("canonical record"));
        AttestedAnchor {
            record,
            signature: signer.sign(&message).to_bytes(),
        }
    }

    impl RemoteAnchorTransport for ScriptedRemote {
        fn read(&self) -> Result<AttestedAnchor, TransportError> {
            if let Some(error) = self.fail_read {
                return Err(error);
            }
            Ok(signed(self.current.clone(), &self.signer))
        }

        fn compare_and_swap(
            &mut self,
            expected: &AnchorRecord,
            next: &AnchorRecord,
        ) -> Result<RemoteSwap, TransportError> {
            if self.conflict || self.current != *expected {
                return Ok(RemoteSwap::PreconditionFailed);
            }
            self.current = next.clone();
            if let Some(error) = self.fail_write {
                return Err(error);
            }
            let mut attested = signed(next.clone(), &self.signer);
            if self.tamper_ack {
                attested.record.sequence += 1;
            }
            Ok(RemoteSwap::Applied(attested))
        }
    }

    fn adapter() -> RemoteAnchorAdapter<ScriptedRemote> {
        let signer = SigningKey::from_bytes(&[41_u8; 32]);
        let public = signer.verifying_key().to_bytes();
        RemoteAnchorAdapter::new(
            ScriptedRemote {
                current: record(),
                fail_read: None,
                fail_write: None,
                conflict: false,
                tamper_ack: false,
                signer,
            },
            public,
        )
    }

    #[test]
    fn signed_read_and_atomic_ack_check_exact_state() {
        let mut client = adapter();
        let before = client.load().unwrap_or_else(|_| panic!("read"));
        let mut next = before.clone();
        next.revision += 1;
        next.sequence += 1;
        next.chain_digest = [2; 32];
        assert_eq!(
            client.compare_and_swap(&before, &next),
            Ok(SwapOutcome::Committed)
        );
        assert_eq!(client.load(), Ok(next));
    }

    #[test]
    fn network_timeout_after_commit_is_not_acknowledged() {
        let mut client = adapter();
        client.transport.fail_write = Some(TransportError::Timeout);
        let before = client.load().unwrap_or_else(|_| panic!("read"));
        let mut next = before.clone();
        next.revision += 1;
        assert_eq!(
            client.compare_and_swap(&before, &next),
            Err(StoreError::UncertainCompletion)
        );
        assert_eq!(client.load(), Ok(next));
    }

    #[test]
    fn stale_cas_conflicts_and_does_not_overwrite() {
        let mut client = adapter();
        client.transport.conflict = true;
        let current = client.load().unwrap_or_else(|_| panic!("read"));
        let mut next = current.clone();
        next.revision += 1;
        assert_eq!(
            client.compare_and_swap(&current, &next),
            Ok(SwapOutcome::Conflict)
        );
        assert_eq!(client.load(), Ok(current));
    }

    #[test]
    fn tampered_ack_and_wrong_response_signer_fail_closed() {
        let mut client = adapter();
        client.transport.tamper_ack = true;
        let current = client.load().unwrap_or_else(|_| panic!("read"));
        let mut next = current.clone();
        next.revision += 1;
        assert_eq!(
            client.compare_and_swap(&current, &next),
            Err(StoreError::IntegrityUncertain)
        );
        let mut client = adapter();
        client.response_public_key = SigningKey::from_bytes(&[42_u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(client.load(), Err(StoreError::IntegrityUncertain));
    }

    #[test]
    fn unavailable_and_invalid_remote_responses_fail_closed() {
        let mut client = adapter();
        client.transport.fail_read = Some(TransportError::Unavailable);
        assert_eq!(client.load(), Err(StoreError::Unavailable));
        client.transport.fail_read = Some(TransportError::InvalidResponse);
        assert_eq!(client.load(), Err(StoreError::IntegrityUncertain));
    }
}
