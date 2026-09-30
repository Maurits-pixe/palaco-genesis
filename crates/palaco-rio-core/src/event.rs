//! Immutable RIO event persistence and deterministic replay primitives.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use palaco_constitution::{IdentityHandle, ProvenanceRecord};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    RioConversationId, RioConversationState, RioMessageId, RioMessageRole, RioSessionId,
    RioSessionState,
};

/// Stable identifier for one persisted RIO event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RioEventId(Uuid);

impl RioEventId {
    /// Creates a new event identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RioEventId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable identifier for one append-only RIO event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RioStreamId(Uuid);

impl RioStreamId {
    /// Creates a new event-stream identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RioStreamId {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 digest binding an event to its canonical predecessor and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RioEventDigest([u8; 32]);

impl RioEventDigest {
    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the digest as lowercase hexadecimal text.
    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }
}

/// Payloads accepted by the RIO runtime event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RioEventPayload {
    /// Records the opening of an active session.
    SessionOpened {
        /// Session being opened.
        session_id: RioSessionId,
        /// Identity bound to the session.
        identity: IdentityHandle,
        /// Surface on which the session was opened.
        surface: String,
    },
    /// Records the opening of a conversation.
    ConversationOpened {
        /// Conversation being opened.
        conversation_id: RioConversationId,
        /// Session owning the conversation.
        session_id: RioSessionId,
        /// Identity bound to the conversation.
        identity: IdentityHandle,
        /// Surface on which the conversation was opened.
        surface: String,
    },
    /// Records one append-only message.
    MessageAppended {
        /// Conversation receiving the message.
        conversation_id: RioConversationId,
        /// Session owning the conversation.
        session_id: RioSessionId,
        /// Message being appended.
        message_id: RioMessageId,
        /// Party that emitted the message.
        role: RioMessageRole,
        /// Message content.
        content: String,
        /// Time at which the message entered the conversation.
        recorded_at: DateTime<Utc>,
        /// Provenance for the message content.
        provenance: ProvenanceRecord,
    },
    /// Records the closure of a conversation.
    ConversationClosed {
        /// Conversation being closed.
        conversation_id: RioConversationId,
        /// Session owning the conversation.
        session_id: RioSessionId,
    },
    /// Records terminal revocation of a session.
    SessionRevoked {
        /// Session being revoked.
        session_id: RioSessionId,
    },
}

impl RioEventPayload {
    fn session_id(&self) -> RioSessionId {
        match self {
            Self::SessionOpened { session_id, .. }
            | Self::ConversationOpened { session_id, .. }
            | Self::MessageAppended { session_id, .. }
            | Self::ConversationClosed { session_id, .. }
            | Self::SessionRevoked { session_id } => *session_id,
        }
    }

    fn conversation_id(&self) -> Option<RioConversationId> {
        match self {
            Self::SessionOpened { .. } | Self::SessionRevoked { .. } => None,
            Self::ConversationOpened {
                conversation_id, ..
            }
            | Self::MessageAppended {
                conversation_id, ..
            }
            | Self::ConversationClosed {
                conversation_id, ..
            } => Some(*conversation_id),
        }
    }

    fn canonical(&self) -> String {
        match self {
            Self::SessionOpened {
                session_id,
                identity,
                surface,
            } => canonical_fields(
                "SESSION_OPENED",
                &[
                    uuid_text(session_id.as_uuid()),
                    identity.subject.clone(),
                    identity.surface.clone(),
                    surface.clone(),
                ],
            ),
            Self::ConversationOpened {
                conversation_id,
                session_id,
                identity,
                surface,
            } => canonical_fields(
                "CONVERSATION_OPENED",
                &[
                    uuid_text(conversation_id.as_uuid()),
                    uuid_text(session_id.as_uuid()),
                    identity.subject.clone(),
                    identity.surface.clone(),
                    surface.clone(),
                ],
            ),
            Self::MessageAppended {
                conversation_id,
                session_id,
                message_id,
                role,
                content,
                recorded_at,
                provenance,
            } => canonical_fields(
                "MESSAGE_APPENDED",
                &[
                    uuid_text(conversation_id.as_uuid()),
                    uuid_text(session_id.as_uuid()),
                    uuid_text(message_id.as_uuid()),
                    role_tag(*role).to_string(),
                    content.clone(),
                    canonical_time(recorded_at),
                    provenance.source.clone(),
                    provenance.record_locator.clone(),
                ],
            ),
            Self::ConversationClosed {
                conversation_id,
                session_id,
            } => canonical_fields(
                "CONVERSATION_CLOSED",
                &[
                    uuid_text(conversation_id.as_uuid()),
                    uuid_text(session_id.as_uuid()),
                ],
            ),
            Self::SessionRevoked { session_id } => {
                canonical_fields("SESSION_REVOKED", &[uuid_text(session_id.as_uuid())])
            }
        }
    }
}

/// Input prepared for an append-only event commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEventInput {
    /// Stable identifier used for idempotent retries.
    pub event_id: RioEventId,
    /// Typed event payload.
    pub payload: RioEventPayload,
    /// Time at which the domain event occurred.
    pub occurred_at: DateTime<Utc>,
    /// Time at which the persistence boundary recorded the event.
    pub recorded_at: DateTime<Utc>,
    /// Provenance for the event itself.
    pub provenance: ProvenanceRecord,
}

impl RioEventInput {
    /// Creates an event input with a caller-supplied stable event identifier.
    pub fn new(
        event_id: RioEventId,
        payload: RioEventPayload,
        occurred_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
        provenance: ProvenanceRecord,
    ) -> Self {
        Self {
            event_id,
            payload,
            occurred_at,
            recorded_at,
            provenance,
        }
    }

    /// Creates a session-opened event input.
    pub fn session_opened(
        session_id: RioSessionId,
        identity: IdentityHandle,
        surface: impl Into<String>,
        occurred_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
        provenance: ProvenanceRecord,
    ) -> Self {
        Self::new(
            RioEventId::new(),
            RioEventPayload::SessionOpened {
                session_id,
                identity,
                surface: surface.into(),
            },
            occurred_at,
            recorded_at,
            provenance,
        )
    }

    /// Creates a conversation-opened event input.
    pub fn conversation_opened(
        conversation_id: RioConversationId,
        session_id: RioSessionId,
        identity: IdentityHandle,
        surface: impl Into<String>,
        occurred_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
        provenance: ProvenanceRecord,
    ) -> Self {
        Self::new(
            RioEventId::new(),
            RioEventPayload::ConversationOpened {
                conversation_id,
                session_id,
                identity,
                surface: surface.into(),
            },
            occurred_at,
            recorded_at,
            provenance,
        )
    }

    /// Creates a conversation-closed event input.
    pub fn conversation_closed(
        conversation_id: RioConversationId,
        session_id: RioSessionId,
        occurred_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
        provenance: ProvenanceRecord,
    ) -> Self {
        Self::new(
            RioEventId::new(),
            RioEventPayload::ConversationClosed {
                conversation_id,
                session_id,
            },
            occurred_at,
            recorded_at,
            provenance,
        )
    }

    /// Creates a session-revoked event input.
    pub fn session_revoked(
        session_id: RioSessionId,
        occurred_at: DateTime<Utc>,
        recorded_at: DateTime<Utc>,
        provenance: ProvenanceRecord,
    ) -> Self {
        Self::new(
            RioEventId::new(),
            RioEventPayload::SessionRevoked { session_id },
            occurred_at,
            recorded_at,
            provenance,
        )
    }
}

/// Persisted event envelope with sequence, provenance and predecessor binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEventEnvelope {
    event_id: RioEventId,
    stream_id: RioStreamId,
    sequence: u64,
    occurred_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    session_id: RioSessionId,
    conversation_id: Option<RioConversationId>,
    provenance: ProvenanceRecord,
    payload: RioEventPayload,
    predecessor_digest: Option<RioEventDigest>,
    event_digest: RioEventDigest,
}

impl RioEventEnvelope {
    /// Returns the stable event identifier.
    pub fn event_id(&self) -> RioEventId {
        self.event_id
    }

    /// Returns the owning event stream identifier.
    pub fn stream_id(&self) -> RioStreamId {
        self.stream_id
    }

    /// Returns the canonical stream sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the domain occurrence time.
    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    /// Returns the persistence recording time.
    pub fn recorded_at(&self) -> DateTime<Utc> {
        self.recorded_at
    }

    /// Returns the session referenced by the event.
    pub fn session_id(&self) -> RioSessionId {
        self.session_id
    }

    /// Returns the conversation referenced by the event, when applicable.
    pub fn conversation_id(&self) -> Option<RioConversationId> {
        self.conversation_id
    }

    /// Returns the event provenance.
    pub fn provenance(&self) -> &ProvenanceRecord {
        &self.provenance
    }

    /// Returns the typed event payload.
    pub fn payload(&self) -> &RioEventPayload {
        &self.payload
    }

    /// Returns the digest of the predecessor event.
    pub fn predecessor_digest(&self) -> Option<RioEventDigest> {
        self.predecessor_digest
    }

    /// Returns the digest of this event.
    pub fn event_digest(&self) -> RioEventDigest {
        self.event_digest
    }

    fn seal(
        stream_id: RioStreamId,
        sequence: u64,
        input: &RioEventInput,
        predecessor_digest: Option<RioEventDigest>,
    ) -> Self {
        let session_id = input.payload.session_id();
        let conversation_id = input.payload.conversation_id();
        let event_digest = compute_event_digest(&RioEventDigestInput {
            event_id: input.event_id,
            stream_id,
            sequence,
            occurred_at: input.occurred_at,
            recorded_at: input.recorded_at,
            session_id,
            conversation_id,
            provenance: &input.provenance,
            payload: &input.payload,
            predecessor_digest,
        });

        Self {
            event_id: input.event_id,
            stream_id,
            sequence,
            occurred_at: input.occurred_at,
            recorded_at: input.recorded_at,
            session_id,
            conversation_id,
            provenance: input.provenance.clone(),
            payload: input.payload.clone(),
            predecessor_digest,
            event_digest,
        }
    }
}

/// Receipt returned after an event is committed or recognized as an idempotent retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RioEventReceipt {
    event_id: RioEventId,
    sequence: u64,
    event_digest: RioEventDigest,
}

impl RioEventReceipt {
    /// Returns the committed event identifier.
    pub fn event_id(&self) -> RioEventId {
        self.event_id
    }

    /// Returns the committed sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the committed event digest.
    pub fn event_digest(&self) -> RioEventDigest {
        self.event_digest
    }
}

/// Reconstructed session state produced by deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioReplaySession {
    /// Session identifier.
    pub id: RioSessionId,
    /// Identity bound to the session.
    pub identity: IdentityHandle,
    /// Surface bound to the session.
    pub surface: String,
    /// Reconstructed lifecycle state.
    pub state: RioSessionState,
    /// Time at which the session was opened.
    pub opened_at: DateTime<Utc>,
    /// Time at which the session was revoked, if it was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Provenance of the opening event.
    pub provenance: ProvenanceRecord,
}

/// Reconstructed message state produced by deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioReplayMessage {
    /// Message identifier.
    pub id: RioMessageId,
    /// Message role.
    pub role: RioMessageRole,
    /// Message content.
    pub content: String,
    /// Time at which the message was recorded.
    pub recorded_at: DateTime<Utc>,
    /// Provenance of the message content.
    pub provenance: ProvenanceRecord,
}

/// Reconstructed conversation state produced by deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioReplayConversation {
    /// Conversation identifier.
    pub id: RioConversationId,
    /// Session owning the conversation.
    pub session_id: RioSessionId,
    /// Identity bound to the conversation.
    pub identity: IdentityHandle,
    /// Surface bound to the conversation.
    pub surface: String,
    /// Reconstructed lifecycle state.
    pub state: RioConversationState,
    /// Time at which the conversation was opened.
    pub created_at: DateTime<Utc>,
    /// Provenance of the opening event.
    pub provenance: ProvenanceRecord,
    messages: Vec<RioReplayMessage>,
}

impl RioReplayConversation {
    /// Returns the immutable replayed message history.
    pub fn messages(&self) -> &[RioReplayMessage] {
        &self.messages
    }
}

/// State reconstructed from an ordered RIO event history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioReplayState {
    stream_id: RioStreamId,
    last_sequence: u64,
    head_digest: Option<RioEventDigest>,
    sessions: BTreeMap<RioSessionId, RioReplaySession>,
    conversations: BTreeMap<RioConversationId, RioReplayConversation>,
    event_provenance: Vec<ProvenanceRecord>,
}

impl RioReplayState {
    /// Returns the event stream identifier.
    pub fn stream_id(&self) -> RioStreamId {
        self.stream_id
    }

    /// Returns the last applied sequence, or zero for an empty stream.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the digest of the last applied event.
    pub fn head_digest(&self) -> Option<RioEventDigest> {
        self.head_digest
    }

    /// Returns all reconstructed sessions in stable identifier order.
    pub fn sessions(&self) -> &BTreeMap<RioSessionId, RioReplaySession> {
        &self.sessions
    }

    /// Returns all reconstructed conversations in stable identifier order.
    pub fn conversations(&self) -> &BTreeMap<RioConversationId, RioReplayConversation> {
        &self.conversations
    }

    /// Returns event provenance in canonical replay order.
    pub fn event_provenance(&self) -> &[ProvenanceRecord] {
        &self.event_provenance
    }

    /// Computes a deterministic digest of the reconstructed state.
    pub fn state_digest(&self) -> RioEventDigest {
        let mut fields = vec![
            "RIO_STATE_V1".to_string(),
            uuid_text(self.stream_id.as_uuid()),
            self.last_sequence.to_string(),
            optional_digest_text(self.head_digest),
        ];

        for session in self.sessions.values() {
            fields.push(canonical_fields(
                "SESSION",
                &[
                    uuid_text(session.id.as_uuid()),
                    session.identity.subject.clone(),
                    session.identity.surface.clone(),
                    session.surface.clone(),
                    session_state_tag(session.state).to_string(),
                    canonical_time(&session.opened_at),
                    optional_time_text(session.revoked_at),
                    session.provenance.source.clone(),
                    session.provenance.record_locator.clone(),
                ],
            ));
        }

        for conversation in self.conversations.values() {
            let mut conversation_fields = vec![
                uuid_text(conversation.id.as_uuid()),
                uuid_text(conversation.session_id.as_uuid()),
                conversation.identity.subject.clone(),
                conversation.identity.surface.clone(),
                conversation.surface.clone(),
                conversation_state_tag(conversation.state).to_string(),
                canonical_time(&conversation.created_at),
                conversation.provenance.source.clone(),
                conversation.provenance.record_locator.clone(),
            ];
            for message in &conversation.messages {
                conversation_fields.push(canonical_fields(
                    "MESSAGE",
                    &[
                        uuid_text(message.id.as_uuid()),
                        role_tag(message.role).to_string(),
                        message.content.clone(),
                        canonical_time(&message.recorded_at),
                        message.provenance.source.clone(),
                        message.provenance.record_locator.clone(),
                    ],
                ));
            }
            fields.push(canonical_fields("CONVERSATION", &conversation_fields));
        }

        for provenance in &self.event_provenance {
            fields.push(canonical_fields(
                "EVENT_PROVENANCE",
                &[provenance.source.clone(), provenance.record_locator.clone()],
            ));
        }

        digest_strings(&fields)
    }
}

/// Snapshot of replayed state bound to one exact event-stream head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEventSnapshot {
    stream_id: RioStreamId,
    last_sequence: u64,
    head_digest: Option<RioEventDigest>,
    state: RioReplayState,
}

impl RioEventSnapshot {
    /// Returns the bound stream identifier.
    pub fn stream_id(&self) -> RioStreamId {
        self.stream_id
    }

    /// Returns the last sequence included in the snapshot.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the event digest at the snapshot head.
    pub fn head_digest(&self) -> Option<RioEventDigest> {
        self.head_digest
    }

    /// Returns the reconstructed state captured by the snapshot.
    pub fn state(&self) -> &RioReplayState {
        &self.state
    }
}

/// Errors found while validating or replaying an immutable event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RioReplayError {
    /// An event did not carry both required provenance fields.
    EmptyEventProvenance,
    /// An event belongs to another stream.
    StreamMismatch,
    /// The canonical sequence contains a gap or reordering.
    SequenceGap {
        /// Sequence that was expected.
        expected: u64,
        /// Sequence that was found.
        found: u64,
    },
    /// The predecessor digest does not match the replay head.
    PredecessorMismatch,
    /// The event digest does not match its canonical contents.
    DigestMismatch,
    /// A session identifier was opened more than once.
    DuplicateSession,
    /// A referenced session does not exist.
    UnknownSession,
    /// A session was revoked more than once.
    SessionAlreadyRevoked,
    /// A conversation identifier was opened more than once.
    DuplicateConversation,
    /// A conversation identity or surface does not match its session.
    ConversationIdentityMismatch,
    /// A conversation references another session.
    ConversationSessionMismatch,
    /// A referenced conversation does not exist.
    UnknownConversation,
    /// A message or close event requires an active conversation.
    ConversationClosed,
    /// A message references another session than its conversation.
    MessageSessionMismatch,
    /// A message was attempted after session revocation.
    SessionRevoked,
    /// A message identifier was repeated in one conversation.
    DuplicateMessage,
    /// A message with only whitespace content was persisted.
    EmptyMessageContent,
    /// A snapshot belongs to another stream.
    SnapshotStreamMismatch,
    /// A snapshot claims a sequence beyond the available event history.
    SnapshotAhead,
    /// Snapshot state does not match its validated event prefix.
    SnapshotStateMismatch,
    /// Snapshot head digest does not match its validated event prefix.
    SnapshotHeadMismatch,
}

/// Errors that prevent a persistence commit from being reported successful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RioPersistenceError {
    /// The persistence boundary is unavailable; no event was committed.
    PersistenceUnavailable,
    /// An empty batch cannot represent a commit.
    EmptyBatch,
    /// An existing event identifier was reused with different contents.
    EventIdConflict,
    /// The next sequence could not be represented.
    SequenceOverflow,
    /// Candidate history failed deterministic replay validation.
    Rejected(RioReplayError),
}

/// Append-only reference event store for the RIO runtime.
///
/// This is an in-memory persistence adapter. It proves commit, chain and replay
/// semantics without claiming PostgreSQL durability or production deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEventStore {
    stream_id: RioStreamId,
    writable: bool,
    events: Vec<RioEventEnvelope>,
}

impl RioEventStore {
    /// Creates an empty writable event store for one stream.
    pub fn new(stream_id: RioStreamId) -> Self {
        Self {
            stream_id,
            writable: true,
            events: Vec::new(),
        }
    }

    /// Returns the event stream identifier.
    pub fn stream_id(&self) -> RioStreamId {
        self.stream_id
    }

    /// Returns the immutable event history.
    pub fn events(&self) -> &[RioEventEnvelope] {
        &self.events
    }

    /// Returns the number of committed events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns true when no event has been committed.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Controls the reference persistence boundary for failure-path testing.
    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }

    /// Appends one event and returns its commit receipt.
    pub fn append(&mut self, input: RioEventInput) -> Result<RioEventReceipt, RioPersistenceError> {
        let mut receipts = self.append_batch(vec![input])?;
        receipts.pop().ok_or(RioPersistenceError::EmptyBatch)
    }

    /// Atomically appends a batch after validating its complete candidate history.
    pub fn append_batch(
        &mut self,
        inputs: Vec<RioEventInput>,
    ) -> Result<Vec<RioEventReceipt>, RioPersistenceError> {
        if inputs.is_empty() {
            return Err(RioPersistenceError::EmptyBatch);
        }
        if !self.writable {
            return Err(RioPersistenceError::PersistenceUnavailable);
        }

        let mut new_inputs = Vec::with_capacity(inputs.len());
        for input in &inputs {
            if let Some(existing) = self
                .events
                .iter()
                .find(|event| event.event_id() == input.event_id)
            {
                if !envelope_matches_input(existing, input) {
                    return Err(RioPersistenceError::EventIdConflict);
                }
                continue;
            }

            if new_inputs
                .iter()
                .any(|queued: &RioEventInput| queued.event_id == input.event_id)
            {
                return Err(RioPersistenceError::EventIdConflict);
            }
            new_inputs.push(input.clone());
        }

        if !new_inputs.is_empty() {
            let mut candidate = self.events.clone();
            let mut sequence = u64::try_from(candidate.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(RioPersistenceError::SequenceOverflow)?;
            let mut predecessor_digest = candidate.last().map(|event| event.event_digest());
            let mut new_envelopes = Vec::with_capacity(new_inputs.len());

            for input in &new_inputs {
                let envelope =
                    RioEventEnvelope::seal(self.stream_id, sequence, input, predecessor_digest);
                predecessor_digest = Some(envelope.event_digest());
                candidate.push(envelope.clone());
                new_envelopes.push(envelope);
                sequence = sequence
                    .checked_add(1)
                    .ok_or(RioPersistenceError::SequenceOverflow)?;
            }

            replay_events(self.stream_id, &candidate).map_err(RioPersistenceError::Rejected)?;
            self.events.extend(new_envelopes);
        }

        inputs
            .iter()
            .map(|input| {
                self.events
                    .iter()
                    .find(|event| event.event_id() == input.event_id)
                    .map(receipt_from_event)
                    .ok_or(RioPersistenceError::EventIdConflict)
            })
            .collect()
    }

    /// Reconstructs runtime state from the complete immutable event history.
    pub fn replay(&self) -> Result<RioReplayState, RioReplayError> {
        replay_events(self.stream_id, &self.events)
    }

    /// Creates a snapshot bound to the current validated event-stream head.
    pub fn snapshot(&self) -> Result<RioEventSnapshot, RioReplayError> {
        let state = self.replay()?;
        Ok(RioEventSnapshot {
            stream_id: self.stream_id,
            last_sequence: state.last_sequence,
            head_digest: state.head_digest,
            state,
        })
    }

    /// Replays the suffix after a snapshot without allowing the snapshot to
    /// bypass prefix or revocation validation.
    pub fn replay_from_snapshot(
        &self,
        snapshot: &RioEventSnapshot,
    ) -> Result<RioReplayState, RioReplayError> {
        if snapshot.stream_id != self.stream_id || snapshot.state.stream_id != self.stream_id {
            return Err(RioReplayError::SnapshotStreamMismatch);
        }
        if snapshot.state.last_sequence != snapshot.last_sequence
            || snapshot.state.head_digest != snapshot.head_digest
        {
            return Err(RioReplayError::SnapshotStateMismatch);
        }

        let prefix_len =
            usize::try_from(snapshot.last_sequence).map_err(|_| RioReplayError::SnapshotAhead)?;
        if prefix_len > self.events.len() {
            return Err(RioReplayError::SnapshotAhead);
        }

        let prefix_state = replay_events(self.stream_id, &self.events[..prefix_len])?;
        if prefix_state.state_digest() != snapshot.state.state_digest() {
            return Err(RioReplayError::SnapshotStateMismatch);
        }
        if prefix_state.head_digest != snapshot.head_digest {
            return Err(RioReplayError::SnapshotHeadMismatch);
        }

        let mut state = snapshot.state.clone();
        for event in &self.events[prefix_len..] {
            apply_event(&mut state, event)?;
        }
        Ok(state)
    }
}

fn replay_events(
    stream_id: RioStreamId,
    events: &[RioEventEnvelope],
) -> Result<RioReplayState, RioReplayError> {
    let mut state = RioReplayState {
        stream_id,
        last_sequence: 0,
        head_digest: None,
        sessions: BTreeMap::new(),
        conversations: BTreeMap::new(),
        event_provenance: Vec::with_capacity(events.len()),
    };

    for event in events {
        apply_event(&mut state, event)?;
    }
    Ok(state)
}

fn apply_event(state: &mut RioReplayState, event: &RioEventEnvelope) -> Result<(), RioReplayError> {
    if event.stream_id != state.stream_id {
        return Err(RioReplayError::StreamMismatch);
    }

    let expected_sequence =
        state
            .last_sequence
            .checked_add(1)
            .ok_or(RioReplayError::SequenceGap {
                expected: u64::MAX,
                found: event.sequence,
            })?;
    if event.sequence != expected_sequence {
        return Err(RioReplayError::SequenceGap {
            expected: expected_sequence,
            found: event.sequence,
        });
    }

    if event.predecessor_digest != state.head_digest {
        return Err(RioReplayError::PredecessorMismatch);
    }
    if !has_provenance(&event.provenance) {
        return Err(RioReplayError::EmptyEventProvenance);
    }

    let expected_digest = compute_event_digest(&RioEventDigestInput {
        event_id: event.event_id,
        stream_id: event.stream_id,
        sequence: event.sequence,
        occurred_at: event.occurred_at,
        recorded_at: event.recorded_at,
        session_id: event.session_id,
        conversation_id: event.conversation_id,
        provenance: &event.provenance,
        payload: &event.payload,
        predecessor_digest: event.predecessor_digest,
    });
    if event.event_digest != expected_digest {
        return Err(RioReplayError::DigestMismatch);
    }

    apply_payload(state, event)?;
    state.event_provenance.push(event.provenance.clone());
    state.last_sequence = event.sequence;
    state.head_digest = Some(event.event_digest);
    Ok(())
}

fn apply_payload(
    state: &mut RioReplayState,
    event: &RioEventEnvelope,
) -> Result<(), RioReplayError> {
    match &event.payload {
        RioEventPayload::SessionOpened {
            session_id,
            identity,
            surface,
        } => {
            if state.sessions.contains_key(session_id) {
                return Err(RioReplayError::DuplicateSession);
            }

            state.sessions.insert(
                *session_id,
                RioReplaySession {
                    id: *session_id,
                    identity: identity.clone(),
                    surface: surface.clone(),
                    state: RioSessionState::Active,
                    opened_at: event.occurred_at,
                    revoked_at: None,
                    provenance: event.provenance.clone(),
                },
            );
        }
        RioEventPayload::ConversationOpened {
            conversation_id,
            session_id,
            identity,
            surface,
        } => {
            if state.conversations.contains_key(conversation_id) {
                return Err(RioReplayError::DuplicateConversation);
            }

            let session = state
                .sessions
                .get(session_id)
                .ok_or(RioReplayError::UnknownSession)?;
            if session.state == RioSessionState::Revoked {
                return Err(RioReplayError::SessionRevoked);
            }
            if session.identity != *identity || session.surface != *surface {
                return Err(RioReplayError::ConversationIdentityMismatch);
            }

            state.conversations.insert(
                *conversation_id,
                RioReplayConversation {
                    id: *conversation_id,
                    session_id: *session_id,
                    identity: identity.clone(),
                    surface: surface.clone(),
                    state: RioConversationState::Active,
                    created_at: event.occurred_at,
                    provenance: event.provenance.clone(),
                    messages: Vec::new(),
                },
            );
        }
        RioEventPayload::MessageAppended {
            conversation_id,
            session_id,
            message_id,
            role,
            content,
            recorded_at,
            provenance,
        } => {
            if content.trim().is_empty() {
                return Err(RioReplayError::EmptyMessageContent);
            }

            let session = state
                .sessions
                .get(session_id)
                .ok_or(RioReplayError::UnknownSession)?;
            if session.state == RioSessionState::Revoked {
                return Err(RioReplayError::SessionRevoked);
            }

            let conversation = state
                .conversations
                .get_mut(conversation_id)
                .ok_or(RioReplayError::UnknownConversation)?;
            if conversation.session_id != *session_id {
                return Err(RioReplayError::MessageSessionMismatch);
            }
            if conversation.state == RioConversationState::Closed {
                return Err(RioReplayError::ConversationClosed);
            }
            if conversation
                .messages
                .iter()
                .any(|message| message.id == *message_id)
            {
                return Err(RioReplayError::DuplicateMessage);
            }

            conversation.messages.push(RioReplayMessage {
                id: *message_id,
                role: *role,
                content: content.clone(),
                recorded_at: *recorded_at,
                provenance: provenance.clone(),
            });
        }
        RioEventPayload::ConversationClosed {
            conversation_id,
            session_id,
        } => {
            let conversation = state
                .conversations
                .get_mut(conversation_id)
                .ok_or(RioReplayError::UnknownConversation)?;
            if conversation.session_id != *session_id {
                return Err(RioReplayError::ConversationSessionMismatch);
            }
            if conversation.state == RioConversationState::Closed {
                return Err(RioReplayError::ConversationClosed);
            }
            conversation.state = RioConversationState::Closed;
        }
        RioEventPayload::SessionRevoked { session_id } => {
            let session = state
                .sessions
                .get_mut(session_id)
                .ok_or(RioReplayError::UnknownSession)?;
            if session.state == RioSessionState::Revoked {
                return Err(RioReplayError::SessionAlreadyRevoked);
            }
            session.state = RioSessionState::Revoked;
            session.revoked_at = Some(event.occurred_at);
        }
    }

    Ok(())
}

fn envelope_matches_input(envelope: &RioEventEnvelope, input: &RioEventInput) -> bool {
    envelope.event_id == input.event_id
        && envelope.occurred_at == input.occurred_at
        && envelope.recorded_at == input.recorded_at
        && envelope.provenance == input.provenance
        && envelope.payload == input.payload
}

fn receipt_from_event(event: &RioEventEnvelope) -> RioEventReceipt {
    RioEventReceipt {
        event_id: event.event_id,
        sequence: event.sequence,
        event_digest: event.event_digest,
    }
}

struct RioEventDigestInput<'a> {
    event_id: RioEventId,
    stream_id: RioStreamId,
    sequence: u64,
    occurred_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    session_id: RioSessionId,
    conversation_id: Option<RioConversationId>,
    provenance: &'a ProvenanceRecord,
    payload: &'a RioEventPayload,
    predecessor_digest: Option<RioEventDigest>,
}

fn compute_event_digest(input: &RioEventDigestInput<'_>) -> RioEventDigest {
    digest_strings(&[
        "RIO_EVENT_V1".to_string(),
        uuid_text(input.event_id.as_uuid()),
        uuid_text(input.stream_id.as_uuid()),
        input.sequence.to_string(),
        canonical_time(&input.occurred_at),
        canonical_time(&input.recorded_at),
        uuid_text(input.session_id.as_uuid()),
        optional_uuid_text(input.conversation_id),
        input.provenance.source.clone(),
        input.provenance.record_locator.clone(),
        input.payload.canonical(),
        optional_digest_text(input.predecessor_digest),
    ])
}

fn digest_strings(fields: &[String]) -> RioEventDigest {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(canonical_field(field).as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    RioEventDigest(bytes)
}

fn canonical_fields(tag: &str, fields: &[String]) -> String {
    let mut values = Vec::with_capacity(fields.len() + 1);
    values.push(tag.to_string());
    values.extend(fields.iter().cloned());
    values
        .iter()
        .map(|value| canonical_field(value))
        .collect::<Vec<_>>()
        .join("")
}

fn canonical_field(value: &str) -> String {
    format!("{}:{}", value.len(), value)
}

fn canonical_time(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn optional_time_text(value: Option<DateTime<Utc>>) -> String {
    value
        .as_ref()
        .map(canonical_time)
        .unwrap_or_else(|| "NONE".to_string())
}

fn optional_uuid_text(value: Option<RioConversationId>) -> String {
    value
        .map(|conversation_id| uuid_text(conversation_id.as_uuid()))
        .unwrap_or_else(|| "NONE".to_string())
}

fn optional_digest_text(value: Option<RioEventDigest>) -> String {
    value
        .map(|digest| digest.to_hex())
        .unwrap_or_else(|| "NONE".to_string())
}

fn uuid_text(value: Uuid) -> String {
    value.to_string()
}

fn role_tag(role: RioMessageRole) -> &'static str {
    match role {
        RioMessageRole::Human => "HUMAN",
        RioMessageRole::Rio => "RIO",
    }
}

fn session_state_tag(state: RioSessionState) -> &'static str {
    match state {
        RioSessionState::Active => "ACTIVE",
        RioSessionState::Revoked => "REVOKED",
    }
}

fn conversation_state_tag(state: RioConversationState) -> &'static str {
    match state {
        RioConversationState::Active => "ACTIVE",
        RioConversationState::Closed => "CLOSED",
    }
}

fn has_provenance(provenance: &ProvenanceRecord) -> bool {
    !provenance.source.trim().is_empty() && !provenance.record_locator.trim().is_empty()
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
    use super::*;
    use crate::RioSession;

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

    #[test]
    fn append_and_replay_reconstructs_the_complete_lifecycle() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let session = RioSession::open(identity(), "rio-web", provenance("session"), now(0));
        let conversation_id = RioConversationId::new();
        let message_id = RioMessageId::new();
        let mut store = RioEventStore::new(stream_id);

        let inputs = vec![
            RioEventInput::session_opened(
                session.id,
                session.identity.clone(),
                session.surface.clone(),
                now(0),
                now(1),
                provenance("event/session-opened"),
            ),
            RioEventInput::conversation_opened(
                conversation_id,
                session.id,
                session.identity.clone(),
                session.surface.clone(),
                now(2),
                now(3),
                provenance("event/conversation-opened"),
            ),
            RioEventInput::new(
                RioEventId::new(),
                RioEventPayload::MessageAppended {
                    conversation_id,
                    session_id: session.id,
                    message_id,
                    role: RioMessageRole::Human,
                    content: "Hello RIO".to_string(),
                    recorded_at: now(4),
                    provenance: provenance("message/content"),
                },
                now(4),
                now(5),
                provenance("event/message-appended"),
            ),
            RioEventInput::conversation_closed(
                conversation_id,
                session.id,
                now(6),
                now(7),
                provenance("event/conversation-closed"),
            ),
            RioEventInput::session_revoked(
                session.id,
                now(8),
                now(9),
                provenance("event/session-revoked"),
            ),
        ];

        let receipts = store
            .append_batch(inputs)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(receipts.len(), 5);
        assert_eq!(
            store
                .events()
                .iter()
                .map(RioEventEnvelope::sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );

        let state = store.replay().map_err(|error| format!("{error:?}"))?;
        assert_eq!(state.last_sequence(), 5);
        assert_eq!(
            state.sessions().get(&session.id).map(|value| value.state),
            Some(RioSessionState::Revoked)
        );
        let conversation = state
            .conversations()
            .get(&conversation_id)
            .ok_or_else(|| "conversation missing".to_string())?;
        assert_eq!(conversation.state, RioConversationState::Closed);
        assert_eq!(conversation.messages().len(), 1);
        assert_eq!(state.event_provenance().len(), 5);
        Ok(())
    }

    #[test]
    fn sequence_orders_events_even_when_wall_clock_metadata_is_not_monotone() {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let conversation_id = RioConversationId::new();
        let mut store = RioEventStore::new(stream_id);

        let opened = RioEventInput::session_opened(
            session_id,
            identity(),
            "rio-web",
            now(100),
            now(100),
            provenance("event/session"),
        );
        let conversation = RioEventInput::conversation_opened(
            conversation_id,
            session_id,
            identity(),
            "rio-web",
            now(10),
            now(10),
            provenance("event/conversation"),
        );

        assert!(store.append(opened).is_ok());
        assert!(store.append(conversation).is_ok());
        assert_eq!(store.events()[0].sequence(), 1);
        assert_eq!(store.events()[1].sequence(), 2);
        assert!(store.replay().is_ok());
    }

    #[test]
    fn revocation_survives_snapshot_replay() -> Result<(), String> {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let mut store = RioEventStore::new(stream_id);
        store
            .append(RioEventInput::session_opened(
                session_id,
                identity(),
                "rio-web",
                now(0),
                now(0),
                provenance("event/session"),
            ))
            .map_err(|error| format!("{error:?}"))?;
        store
            .append(RioEventInput::session_revoked(
                session_id,
                now(1),
                now(1),
                provenance("event/revoked"),
            ))
            .map_err(|error| format!("{error:?}"))?;

        let snapshot = store.snapshot().map_err(|error| format!("{error:?}"))?;
        let restored = store
            .replay_from_snapshot(&snapshot)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            restored
                .sessions()
                .get(&session_id)
                .map(|value| value.state),
            Some(RioSessionState::Revoked)
        );
        assert_eq!(restored.last_sequence(), snapshot.last_sequence());
        Ok(())
    }

    #[test]
    fn persistence_failure_does_not_report_or_leave_a_commit() {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let mut store = RioEventStore::new(stream_id);
        store.set_writable(false);

        let result = store.append(RioEventInput::session_opened(
            session_id,
            identity(),
            "rio-web",
            now(0),
            now(0),
            provenance("event/session"),
        ));

        assert_eq!(result, Err(RioPersistenceError::PersistenceUnavailable));
        assert!(store.is_empty());
    }

    #[test]
    fn rejected_batch_is_atomic() {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let conversation_id = RioConversationId::new();
        let mut store = RioEventStore::new(stream_id);

        assert!(store
            .append(RioEventInput::session_opened(
                session_id,
                identity(),
                "rio-web",
                now(0),
                now(0),
                provenance("event/session"),
            ))
            .is_ok());

        let invalid_batch = vec![
            RioEventInput::conversation_opened(
                conversation_id,
                RioSessionId::new(),
                identity(),
                "rio-web",
                now(1),
                now(1),
                provenance("event/invalid-conversation"),
            ),
            RioEventInput::session_revoked(session_id, now(2), now(2), provenance("event/revoked")),
        ];

        assert!(matches!(
            store.append_batch(invalid_batch),
            Err(RioPersistenceError::Rejected(
                RioReplayError::UnknownSession
            ))
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn same_event_retry_is_idempotent_but_changed_content_conflicts() {
        let stream_id = RioStreamId::new();
        let session_id = RioSessionId::new();
        let event_id = RioEventId::new();
        let input = RioEventInput::new(
            event_id,
            RioEventPayload::SessionOpened {
                session_id,
                identity: identity(),
                surface: "rio-web".to_string(),
            },
            now(0),
            now(0),
            provenance("event/session"),
        );
        let mut store = RioEventStore::new(stream_id);
        let first = store.append(input.clone());
        let second = store.append(input);
        assert!(first.is_ok());
        assert_eq!(first, second);

        let conflict = RioEventInput::new(
            event_id,
            RioEventPayload::SessionOpened {
                session_id,
                identity: identity(),
                surface: "rio-mobile".to_string(),
            },
            now(0),
            now(0),
            provenance("event/session"),
        );
        assert_eq!(
            store.append(conflict),
            Err(RioPersistenceError::EventIdConflict)
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn missing_event_provenance_is_rejected_before_commit() {
        let mut store = RioEventStore::new(RioStreamId::new());
        let result = store.append(RioEventInput::session_opened(
            RioSessionId::new(),
            identity(),
            "rio-web",
            now(0),
            now(0),
            ProvenanceRecord::default(),
        ));
        assert_eq!(
            result,
            Err(RioPersistenceError::Rejected(
                RioReplayError::EmptyEventProvenance
            ))
        );
        assert!(store.is_empty());
    }
}
