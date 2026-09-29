//! RIO persistence adapter and outbox transaction boundary.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::{
    RioEventDigest, RioEventEnvelope, RioEventInput, RioEventReceipt, RioEventStore,
    RioPersistenceError, RioReplayError, RioReplayState, RioStreamId,
};

/// A commit request carrying the optimistic stream revision and retry identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioCommitRequest {
    /// Stream that must receive the events.
    pub stream_id: RioStreamId,
    /// Last applied sequence expected by the caller before this commit.
    pub expected_sequence: u64,
    /// Stable caller key used to recognize an identical retry.
    pub idempotency_key: String,
    /// Ordered event inputs to append as one commit.
    pub events: Vec<RioEventInput>,
}

impl RioCommitRequest {
    /// Creates a persistence request with a caller-supplied retry key.
    pub fn new(
        stream_id: RioStreamId,
        expected_sequence: u64,
        idempotency_key: impl Into<String>,
        events: Vec<RioEventInput>,
    ) -> Self {
        Self {
            stream_id,
            expected_sequence,
            idempotency_key: idempotency_key.into(),
            events,
        }
    }

    fn fingerprint(&self) -> String {
        let mut fields = vec![
            "RIO_COMMIT_V1".to_string(),
            self.stream_id.as_uuid().to_string(),
            self.expected_sequence.to_string(),
            self.idempotency_key.clone(),
        ];
        fields.extend(
            self.events
                .iter()
                .map(RioEventInput::canonical_for_adapter),
        );
        digest_fields(&fields)
    }
}

/// Delivery state of a record placed in the reference outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioOutboxState {
    /// The event is available for a future at-least-once dispatcher.
    Pending,
}

/// Immutable outbox record paired with one committed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioOutboxRecord {
    event: RioEventEnvelope,
    state: RioOutboxState,
}

impl RioOutboxRecord {
    /// Returns the event represented by this outbox record.
    pub fn event(&self) -> &RioEventEnvelope {
        &self.event
    }

    /// Returns the current reference outbox state.
    pub fn state(&self) -> RioOutboxState {
        self.state
    }

    /// Returns the stable event identifier.
    pub fn event_id(&self) -> crate::RioEventId {
        self.event.event_id()
    }

    /// Returns the canonical event sequence.
    pub fn sequence(&self) -> u64 {
        self.event.sequence()
    }

    /// Returns the event digest bound into the outbox record.
    pub fn event_digest(&self) -> RioEventDigest {
        self.event.event_digest()
    }
}

/// Receipt for an accepted commit, including its projection and event results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioCommitReceipt {
    idempotency_key: String,
    request_fingerprint: String,
    event_receipts: Vec<RioEventReceipt>,
    projection_state_digest: RioEventDigest,
}

impl RioCommitReceipt {
    /// Returns the idempotency key associated with the commit.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Returns the canonical request fingerprint used for retry matching.
    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    /// Returns receipts for the requested events in request order.
    pub fn event_receipts(&self) -> &[RioEventReceipt] {
        &self.event_receipts
    }

    /// Returns the deterministic digest of the replayed projection after commit.
    pub fn projection_state_digest(&self) -> RioEventDigest {
        self.projection_state_digest
    }
}

/// Errors that prevent a persistence adapter commit from being reported successful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RioPersistenceAdapterError {
    /// The request did not include a non-whitespace idempotency key.
    EmptyIdempotencyKey,
    /// The request targeted a different stream than this adapter owns.
    StreamMismatch,
    /// The caller's optimistic revision did not match the current stream head.
    RevisionConflict {
        /// Revision supplied by the caller.
        expected: u64,
        /// Revision currently present in the adapter.
        actual: u64,
    },
    /// The key was already used with different canonical request material.
    IdempotencyConflict,
    /// The outbox boundary was unavailable; no candidate was committed.
    OutboxUnavailable,
    /// Existing event and outbox histories were not aligned.
    OutboxInvariantViolation,
    /// The append-only event store rejected the candidate.
    EventStore(RioPersistenceError),
    /// Existing history could not be replayed before the commit.
    HistoryInvalid(RioReplayError),
    /// The candidate projection could not be reconstructed after append.
    ProjectionReplayRejected(RioReplayError),
}

/// Contract for a RIO repository and its atomic event/outbox boundary.
pub trait RioPersistenceAdapter {
    /// Commits events with optimistic revision and idempotency enforcement.
    fn commit(
        &mut self,
        request: RioCommitRequest,
    ) -> Result<RioCommitReceipt, RioPersistenceAdapterError>;

    /// Returns the stream owned by this adapter.
    fn stream_id(&self) -> RioStreamId;

    /// Returns the immutable committed event history.
    fn events(&self) -> &[RioEventEnvelope];

    /// Returns outbox records created by successful commits.
    fn outbox(&self) -> &[RioOutboxRecord];

    /// Reconstructs the projection from the complete event history.
    fn replay(&self) -> Result<RioReplayState, RioReplayError>;
}

/// Executable reference implementation of the RIO persistence boundary.
///
/// The adapter uses candidate copies and swaps them only after event validation,
/// projection replay and outbox construction all succeed. It is an in-memory
/// contract implementation, not a PostgreSQL driver or durability claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioReferencePersistenceAdapter {
    store: RioEventStore,
    outbox: Vec<RioOutboxRecord>,
    idempotency: BTreeMap<String, RioCommitReceipt>,
    outbox_writable: bool,
}

impl RioReferencePersistenceAdapter {
    /// Creates an empty writable reference adapter for one stream.
    pub fn new(stream_id: RioStreamId) -> Self {
        Self {
            store: RioEventStore::new(stream_id),
            outbox: Vec::new(),
            idempotency: BTreeMap::new(),
            outbox_writable: true,
        }
    }

    /// Controls the reference outbox boundary for failure-path testing.
    pub fn set_outbox_writable(&mut self, writable: bool) {
        self.outbox_writable = writable;
    }

    /// Controls the underlying reference event-store boundary for failure tests.
    pub fn set_event_writable(&mut self, writable: bool) {
        self.store.set_writable(writable);
    }

    /// Commits an event batch and its pending outbox records atomically.
    pub fn commit(
        &mut self,
        request: RioCommitRequest,
    ) -> Result<RioCommitReceipt, RioPersistenceAdapterError> {
        if request.stream_id != self.store.stream_id() {
            return Err(RioPersistenceAdapterError::StreamMismatch);
        }
        if request.idempotency_key.trim().is_empty() {
            return Err(RioPersistenceAdapterError::EmptyIdempotencyKey);
        }

        validate_outbox_alignment(self.store.events(), &self.outbox)?;

        let request_fingerprint = request.fingerprint();
        if let Some(existing) = self.idempotency.get(&request.idempotency_key) {
            if existing.request_fingerprint == request_fingerprint {
                return Ok(existing.clone());
            }
            return Err(RioPersistenceAdapterError::IdempotencyConflict);
        }

        let current_state = self
            .store
            .replay()
            .map_err(RioPersistenceAdapterError::HistoryInvalid)?;
        if request.expected_sequence != current_state.last_sequence() {
            return Err(RioPersistenceAdapterError::RevisionConflict {
                expected: request.expected_sequence,
                actual: current_state.last_sequence(),
            });
        }
        if !self.outbox_writable {
            return Err(RioPersistenceAdapterError::OutboxUnavailable);
        }

        let mut candidate_store = self.store.clone();
        let previous_event_count = candidate_store.len();
        let event_receipts = candidate_store
            .append_batch(request.events.clone())
            .map_err(RioPersistenceAdapterError::EventStore)?;
        let candidate_state = candidate_store
            .replay()
            .map_err(RioPersistenceAdapterError::ProjectionReplayRejected)?;

        let mut candidate_outbox = self.outbox.clone();
        for event in &candidate_store.events()[previous_event_count..] {
            candidate_outbox.push(RioOutboxRecord {
                event: event.clone(),
                state: RioOutboxState::Pending,
            });
        }
        validate_outbox_alignment(candidate_store.events(), &candidate_outbox)?;

        let receipt = RioCommitReceipt {
            idempotency_key: request.idempotency_key.clone(),
            request_fingerprint,
            event_receipts,
            projection_state_digest: candidate_state.state_digest(),
        };

        self.store = candidate_store;
        self.outbox = candidate_outbox;
        self.idempotency
            .insert(request.idempotency_key, receipt.clone());
        Ok(receipt)
    }

    /// Returns the stream identifier owned by this adapter.
    pub fn stream_id(&self) -> RioStreamId {
        self.store.stream_id()
    }

    /// Returns the immutable event history.
    pub fn events(&self) -> &[RioEventEnvelope] {
        self.store.events()
    }

    /// Returns pending outbox records in event sequence order.
    pub fn outbox(&self) -> &[RioOutboxRecord] {
        &self.outbox
    }

    /// Reconstructs projection state from the complete event history.
    pub fn replay(&self) -> Result<RioReplayState, RioReplayError> {
        self.store.replay()
    }
}

impl RioPersistenceAdapter for RioReferencePersistenceAdapter {
    fn commit(
        &mut self,
        request: RioCommitRequest,
    ) -> Result<RioCommitReceipt, RioPersistenceAdapterError> {
        RioReferencePersistenceAdapter::commit(self, request)
    }

    fn stream_id(&self) -> RioStreamId {
        RioReferencePersistenceAdapter::stream_id(self)
    }

    fn events(&self) -> &[RioEventEnvelope] {
        RioReferencePersistenceAdapter::events(self)
    }

    fn outbox(&self) -> &[RioOutboxRecord] {
        RioReferencePersistenceAdapter::outbox(self)
    }

    fn replay(&self) -> Result<RioReplayState, RioReplayError> {
        RioReferencePersistenceAdapter::replay(self)
    }
}

fn validate_outbox_alignment(
    events: &[RioEventEnvelope],
    outbox: &[RioOutboxRecord],
) -> Result<(), RioPersistenceAdapterError> {
    if events.len() != outbox.len() {
        return Err(RioPersistenceAdapterError::OutboxInvariantViolation);
    }

    for (event, record) in events.iter().zip(outbox) {
        if event.event_id() != record.event_id()
            || event.sequence() != record.sequence()
            || event.event_digest() != record.event_digest()
        {
            return Err(RioPersistenceAdapterError::OutboxInvariantViolation);
        }
    }
    Ok(())
}

fn digest_fields(fields: &[String]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        let encoded = format!("{}:{}", field.len(), field);
        hasher.update(encoded.as_bytes());
    }
    let digest = hasher.finalize();
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use palaco_constitution::{IdentityHandle, ProvenanceRecord};

    use super::*;
    use crate::{RioEventInput, RioSessionId};

    fn now(second: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_790_000_000 + second, 0).unwrap_or_else(Utc::now)
    }

    fn identity() -> IdentityHandle {
        IdentityHandle {
            subject: "person:test".to_string(),
            surface: "rio-web".to_string(),
        }
    }

    fn provenance(locator: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            source: "rio-test".to_string(),
            record_locator: locator.to_string(),
        }
    }

    fn session_event(session_id: RioSessionId, offset: i64) -> RioEventInput {
        RioEventInput::session_opened(
            session_id,
            identity(),
            "rio-web",
            now(offset),
            now(offset + 1),
            provenance(&format!("event/session-{offset}")),
        )
    }

    fn request(
        stream_id: RioStreamId,
        expected_sequence: u64,
        idempotency_key: &str,
        event: RioEventInput,
    ) -> RioCommitRequest {
        RioCommitRequest::new(
            stream_id,
            expected_sequence,
            idempotency_key,
            vec![event],
        )
    }

    #[test]
    fn commit_appends_events_and_outbox_atomically() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let event = session_event(session_id, 0);
        let event_id = event.event_id;
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);

        let receipt = adapter
            .commit(request(stream_id, 0, "commit-1", event))
            .map_err(|error| format!("{error:?}"))?;

        assert_eq!(receipt.event_receipts().len(), 1);
        assert_eq!(receipt.event_receipts()[0].event_id(), event_id);
        assert_eq!(adapter.events().len(), 1);
        assert_eq!(adapter.outbox().len(), 1);
        assert_eq!(adapter.outbox()[0].state(), RioOutboxState::Pending);
        assert_eq!(
            adapter.outbox()[0].event_digest(),
            receipt.event_receipts()[0].event_digest()
        );

        let state = adapter.replay().map_err(|error| format!("{error:?}"))?;
        assert_eq!(state.last_sequence(), 1);
        assert!(state.sessions().contains_key(&session_id));

        Ok(())
    }

    #[test]
    fn revision_conflict_does_not_mutate() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);
        adapter
            .commit(request(
                stream_id,
                0,
                "commit-1",
                session_event(RioSessionId::new(), 0),
            ))
            .map_err(|error| format!("{error:?}"))?;

        let result = adapter.commit(request(
            stream_id,
            0,
            "commit-2",
            session_event(RioSessionId::new(), 2),
        ));

        assert!(matches!(
            result,
            Err(RioPersistenceAdapterError::RevisionConflict {
                expected: 0,
                actual: 1
            })
        ));
        assert_eq!(adapter.events().len(), 1);
        assert_eq!(adapter.outbox().len(), 1);

        Ok(())
    }

    #[test]
    fn same_idempotency_request_retries_without_duplicate() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let event = session_event(RioSessionId::new(), 0);
        let commit = request(stream_id, 0, "commit-1", event);
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);

        let first = adapter
            .commit(commit.clone())
            .map_err(|error| format!("{error:?}"))?;
        let second = adapter
            .commit(commit)
            .map_err(|error| format!("{error:?}"))?;

        assert_eq!(first, second);
        assert_eq!(adapter.events().len(), 1);
        assert_eq!(adapter.outbox().len(), 1);

        Ok(())
    }

    #[test]
    fn changed_idempotency_fingerprint_is_rejected() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let event = session_event(RioSessionId::new(), 0);
        let first_request = request(stream_id, 0, "commit-1", event.clone());
        let mut changed_event = event;
        changed_event.recorded_at = now(9);
        let changed_request = request(stream_id, 0, "commit-1", changed_event);
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);

        adapter
            .commit(first_request)
            .map_err(|error| format!("{error:?}"))?;
        let result = adapter.commit(changed_request);

        assert_eq!(
            result,
            Err(RioPersistenceAdapterError::IdempotencyConflict)
        );
        assert_eq!(adapter.events().len(), 1);
        assert_eq!(adapter.outbox().len(), 1);

        Ok(())
    }

    #[test]
    fn outbox_failure_rolls_back_event_candidate() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);
        adapter.set_outbox_writable(false);

        let result = adapter.commit(request(
            stream_id,
            0,
            "commit-1",
            session_event(RioSessionId::new(), 0),
        ));

        assert_eq!(result, Err(RioPersistenceAdapterError::OutboxUnavailable));
        assert!(adapter.events().is_empty());
        assert!(adapter.outbox().is_empty());

        Ok(())
    }

    #[test]
    fn event_store_failure_never_reports_success() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);
        adapter.set_event_writable(false);

        let result = adapter.commit(request(
            stream_id,
            0,
            "commit-1",
            session_event(RioSessionId::new(), 0),
        ));

        assert_eq!(
            result,
            Err(RioPersistenceAdapterError::EventStore(
                RioPersistenceError::PersistenceUnavailable
            ))
        );
        assert!(adapter.events().is_empty());
        assert!(adapter.outbox().is_empty());

        Ok(())
    }

    #[test]
    fn empty_idempotency_key_is_rejected_before_mutation() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let mut adapter = RioReferencePersistenceAdapter::new(stream_id);

        let result = adapter.commit(request(
            stream_id,
            0,
            "  ",
            session_event(RioSessionId::new(), 0),
        ));

        assert_eq!(result, Err(RioPersistenceAdapterError::EmptyIdempotencyKey));
        assert!(adapter.events().is_empty());
        assert!(adapter.outbox().is_empty());

        Ok(())
    }

    #[test]
    fn commit_fingerprint_is_deterministic() {
        let stream_id = RioStreamId::new();
        let event = session_event(RioSessionId::new(), 0);
        let first = request(stream_id, 0, "commit-1", event.clone());
        let second = request(stream_id, 0, "commit-1", event);

        assert_eq!(first.fingerprint(), second.fingerprint());
    }
}
