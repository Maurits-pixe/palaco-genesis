//! Policy-checked staging checkpoint adapter using a supplied transport.
//!
//! Does not implement TLS, inspect certificates or make network requests.
//! A real client must independently enforce the policy and produce trustworthy
//! observations; simulated metadata is not independent security evidence.

use crate::independent_checkpoint::{CheckpointError, IndependentCheckpoint};
use crate::remote_anchor_adapter::AttestedAnchor;
use crate::staging_endpoint_policy::{StagingEndpoint, TransportObservation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingTransportError {
    Unavailable,
    Timeout,
    InvalidResponse,
}

/// An audited implementation must enforce origin, TLS, SPKI pin, timeout, no
/// redirects and response length before claiming this observation.
pub trait StagingCheckpointTransport {
    fn get_checkpoint(
        &self,
        origin: &str,
        timeout_ms: u32,
    ) -> Result<(TransportObservation<'_>, Option<AttestedAnchor>), StagingTransportError>;
}

/// A policy boundary which still requires separate Ed25519 verification by the
/// v0.20 reconciliation gate. It never grants admission or authority.
pub struct StagingCheckpointAdapter<T> {
    policy: StagingEndpoint,
    transport: T,
}

impl<T> StagingCheckpointAdapter<T> {
    pub fn new(policy: StagingEndpoint, transport: T) -> Self {
        Self { policy, transport }
    }
}

impl<T: StagingCheckpointTransport> IndependentCheckpoint for StagingCheckpointAdapter<T> {
    fn read(&self) -> Result<Option<AttestedAnchor>, CheckpointError> {
        let (observation, candidate) = self
            .transport
            .get_checkpoint(self.policy.origin(), self.policy.timeout_ms())
            .map_err(|error| match error {
                StagingTransportError::Unavailable => CheckpointError::Unavailable,
                StagingTransportError::Timeout => CheckpointError::Timeout,
                StagingTransportError::InvalidResponse => CheckpointError::InvalidResponse,
            })?;
        self.policy
            .assess(&observation)
            .map_err(|_| CheckpointError::InvalidResponse)?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::{StagingCheckpointAdapter, StagingCheckpointTransport, StagingTransportError};
    use crate::anchor_cas::AnchorRecord;
    use crate::independent_checkpoint::{reconcile, CheckpointError, CheckpointGate, IndependentCheckpoint};
    use crate::remote_anchor_adapter::{attestation_bytes, AttestedAnchor};
    use crate::staging_endpoint_policy::{StagingEndpoint, TransportObservation};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    struct FakeTransport {
        observed_origin: &'static str,
        redirected: bool,
        tls_verified: bool,
        pin: [u8; 32],
        status: u16,
        content_type: &'static str,
        bytes: usize,
        response: Option<AttestedAnchor>,
        error: Option<StagingTransportError>,
    }

    impl StagingCheckpointTransport for FakeTransport {
        fn get_checkpoint(
            &self,
            origin: &str,
            timeout_ms: u32,
        ) -> Result<(TransportObservation<'_>, Option<AttestedAnchor>), StagingTransportError> {
            if origin != "https://checkpoint.example.test" || timeout_ms != 5_000 {
                return Err(StagingTransportError::InvalidResponse);
            }
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok((
                TransportObservation {
                    final_origin: self.observed_origin,
                    redirected: self.redirected,
                    tls_verified: self.tls_verified,
                    peer_spki_sha256: self.pin,
                    status: self.status,
                    content_type: self.content_type,
                    body_len: self.bytes,
                },
                self.response.clone(),
            ))
        }
    }

    fn record() -> AnchorRecord {
        AnchorRecord {
            revision: 1,
            signer_epoch: 5,
            sequence: 1,
            chain_digest: [3; 32],
            signer_id: "signer-a".to_owned(),
            retired_signers: BTreeSet::new(),
        }
    }

    fn signed(key: &SigningKey) -> AttestedAnchor {
        let record = record();
        let bytes = attestation_bytes(&record).unwrap_or_else(|_| panic!("encode"));
        AttestedAnchor { record, signature: key.sign(&bytes).to_bytes() }
    }

    fn transport(response: AttestedAnchor) -> FakeTransport {
        FakeTransport {
            observed_origin: "https://checkpoint.example.test",
            redirected: false,
            tls_verified: true,
            pin: [7; 32],
            status: 200,
            content_type: "application/palaco-checkpoint+json",
            bytes: 200,
            response: Some(response),
            error: None,
        }
    }

    fn adapter(remote: FakeTransport) -> StagingCheckpointAdapter<FakeTransport> {
        let policy = StagingEndpoint::new(
            "https://checkpoint.example.test",
            &["checkpoint.example.test"],
            [7; 32],
            5_000,
        )
        .unwrap_or_else(|_| panic!("valid policy"));
        StagingCheckpointAdapter::new(policy, remote)
    }

    #[test]
    fn accepted_observation_still_requires_signature_reconciliation() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let client = adapter(transport(signed(&key)));
        assert_eq!(
            reconcile(Ok(Some(record())), &client, &key.verifying_key().to_bytes()),
            CheckpointGate::Matched
        );
        let wrong = SigningKey::from_bytes(&[62; 32]);
        assert_eq!(
            reconcile(Ok(Some(record())), &client, &wrong.verifying_key().to_bytes()),
            CheckpointGate::InvalidSignature
        );
    }

    #[test]
    fn redirect_and_tls_downgrade_are_invalid_responses() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let mut remote = transport(signed(&key));
        remote.redirected = true;
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
        let mut remote = transport(signed(&key));
        remote.tls_verified = false;
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
        let mut remote = transport(signed(&key));
        remote.pin = [8; 32];
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
    }

    #[test]
    fn bad_origin_status_and_body_are_invalid_responses() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let mut remote = transport(signed(&key));
        remote.observed_origin = "https://other.example.test";
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
        let mut remote = transport(signed(&key));
        remote.status = 302;
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
        let mut remote = transport(signed(&key));
        remote.bytes = 65_537;
        assert_eq!(adapter(remote).read(), Err(CheckpointError::InvalidResponse));
    }

    #[test]
    fn uncertain_transport_never_returns_a_checkpoint() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let mut remote = transport(signed(&key));
        remote.error = Some(StagingTransportError::Timeout);
        assert_eq!(adapter(remote).read(), Err(CheckpointError::Timeout));
        let mut remote = transport(signed(&key));
        remote.error = Some(StagingTransportError::Unavailable);
        assert_eq!(adapter(remote).read(), Err(CheckpointError::Unavailable));
    }
}
