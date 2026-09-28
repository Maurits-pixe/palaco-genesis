//! RIO conversation and message runtime primitives.

use chrono::{DateTime, Utc};
use palaco_constitution::{IdentityHandle, ProvenanceRecord};
use uuid::Uuid;

use crate::{RioSession, RioSessionId};

/// Stable identifier for a RIO conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RioConversationId(Uuid);

impl RioConversationId {
    /// Creates a new conversation identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RioConversationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable identifier for a RIO message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RioMessageId(Uuid);

impl RioMessageId {
    /// Creates a new message identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RioMessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Communicating party represented by a RIO message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioMessageRole {
    /// Human participant bound to the active session.
    Human,
    /// RIO conversational runtime.
    Rio,
}

/// Lifecycle state of a RIO conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioConversationState {
    /// Conversation accepts messages while its bound session remains active.
    Active,
    /// Conversation has been explicitly closed and cannot accept new messages.
    Closed,
}

/// Failure while attempting to append to a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioConversationError {
    /// The bound session is no longer active.
    SessionRevoked,
    /// The supplied session is not the session bound to this conversation.
    SessionMismatch,
    /// The supplied identity differs from the conversation identity.
    IdentityMismatch,
    /// The supplied surface differs from the conversation surface.
    SurfaceMismatch,
    /// The conversation is closed.
    ConversationClosed,
    /// Empty message content is not accepted.
    EmptyContent,
}

/// Immutable message record appended to a RIO conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioMessage {
    /// Stable message identifier.
    pub id: RioMessageId,
    /// Role that emitted the message.
    pub role: RioMessageRole,
    /// Message content.
    pub content: String,
    /// Time at which the message entered the conversation.
    pub recorded_at: DateTime<Utc>,
    /// Provenance for the message record.
    pub provenance: ProvenanceRecord,
}

/// Runtime conversation bound to one RIO session, identity and surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioConversation {
    /// Stable conversation identifier.
    pub id: RioConversationId,
    /// Session to which this conversation is bound.
    pub session_id: RioSessionId,
    /// Identity bound to the conversation.
    pub identity: IdentityHandle,
    /// Surface on which the conversation was opened.
    pub surface: String,
    /// Conversation lifecycle state.
    pub state: RioConversationState,
    /// Time at which the conversation was opened.
    pub created_at: DateTime<Utc>,
    messages: Vec<RioMessage>,
}

impl RioConversation {
    /// Opens a conversation for an active session.
    pub fn open(session: &RioSession, now: DateTime<Utc>) -> Result<Self, RioConversationError> {
        if !session.is_active() {
            return Err(RioConversationError::SessionRevoked);
        }

        Ok(Self {
            id: RioConversationId::new(),
            session_id: session.id,
            identity: session.identity.clone(),
            surface: session.surface.clone(),
            state: RioConversationState::Active,
            created_at: now,
            messages: Vec::new(),
        })
    }

    /// Returns the append-only message history.
    pub fn messages(&self) -> &[RioMessage] {
        &self.messages
    }

    /// Appends a message after validating the current session boundary.
    pub fn append(
        &mut self,
        session: &RioSession,
        role: RioMessageRole,
        content: impl Into<String>,
        provenance: ProvenanceRecord,
        now: DateTime<Utc>,
    ) -> Result<RioMessageId, RioConversationError> {
        self.validate_session(session)?;

        if self.state != RioConversationState::Active {
            return Err(RioConversationError::ConversationClosed);
        }

        let content = content.into();
        if content.trim().is_empty() {
            return Err(RioConversationError::EmptyContent);
        }

        let message = RioMessage {
            id: RioMessageId::new(),
            role,
            content,
            recorded_at: now,
            provenance,
        };
        let id = message.id;
        self.messages.push(message);
        Ok(id)
    }

    /// Closes the conversation. Existing message history remains available.
    pub fn close(&mut self) {
        self.state = RioConversationState::Closed;
    }

    fn validate_session(&self, session: &RioSession) -> Result<(), RioConversationError> {
        if !session.is_active() {
            return Err(RioConversationError::SessionRevoked);
        }
        if session.id != self.session_id {
            return Err(RioConversationError::SessionMismatch);
        }
        if session.identity != self.identity {
            return Err(RioConversationError::IdentityMismatch);
        }
        if session.surface != self.surface {
            return Err(RioConversationError::SurfaceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RioSession;

    fn identity() -> IdentityHandle {
        IdentityHandle {
            subject: "person:test".to_string(),
            surface: "rio-web".to_string(),
        }
    }

    fn provenance(locator: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            source: "rio-web".to_string(),
            record_locator: locator.to_string(),
        }
    }

    fn session() -> RioSession {
        RioSession::open(
            identity(),
            "rio-web",
            provenance("session-test"),
            Utc::now(),
        )
    }

    #[test]
    fn conversation_opens_for_active_session() -> Result<(), RioConversationError> {
        let session = session();
        let conversation = RioConversation::open(&session, Utc::now())?;
        assert_eq!(conversation.session_id, session.id);
        assert!(conversation.messages().is_empty());
        Ok(())
    }

    #[test]
    fn revoked_session_cannot_open_conversation() {
        let mut session = session();
        session.revoke();
        assert_eq!(
            RioConversation::open(&session, Utc::now()),
            Err(RioConversationError::SessionRevoked)
        );
    }

    #[test]
    fn append_preserves_message_order() -> Result<(), RioConversationError> {
        let session = session();
        let mut conversation = RioConversation::open(&session, Utc::now())?;
        conversation.append(
            &session,
            RioMessageRole::Human,
            "First",
            provenance("message-1"),
            Utc::now(),
        )?;
        conversation.append(
            &session,
            RioMessageRole::Rio,
            "Second",
            provenance("message-2"),
            Utc::now(),
        )?;
        assert_eq!(conversation.messages()[0].content, "First");
        assert_eq!(conversation.messages()[1].content, "Second");
        Ok(())
    }

    #[test]
    fn revoked_session_blocks_future_messages() -> Result<(), RioConversationError> {
        let mut session = session();
        let mut conversation = RioConversation::open(&session, Utc::now())?;
        session.revoke();
        let result = conversation.append(
            &session,
            RioMessageRole::Human,
            "Must not be recorded",
            provenance("message-revoked"),
            Utc::now(),
        );
        assert_eq!(result, Err(RioConversationError::SessionRevoked));
        assert!(conversation.messages().is_empty());
        Ok(())
    }

    #[test]
    fn different_session_cannot_append() -> Result<(), RioConversationError> {
        let session = session();
        let other_session = session();
        let mut conversation = RioConversation::open(&session, Utc::now())?;
        let result = conversation.append(
            &other_session,
            RioMessageRole::Human,
            "Wrong session",
            provenance("message-wrong-session"),
            Utc::now(),
        );
        assert_eq!(result, Err(RioConversationError::SessionMismatch));
        Ok(())
    }

    #[test]
    fn closed_conversation_rejects_messages() -> Result<(), RioConversationError> {
        let session = session();
        let mut conversation = RioConversation::open(&session, Utc::now())?;
        conversation.close();
        let result = conversation.append(
            &session,
            RioMessageRole::Human,
            "Too late",
            provenance("message-closed"),
            Utc::now(),
        );
        assert_eq!(result, Err(RioConversationError::ConversationClosed));
        Ok(())
    }

    #[test]
    fn empty_message_is_rejected() -> Result<(), RioConversationError> {
        let session = session();
        let mut conversation = RioConversation::open(&session, Utc::now())?;
        let result = conversation.append(
            &session,
            RioMessageRole::Human,
            "   ",
            provenance("message-empty"),
            Utc::now(),
        );
        assert_eq!(result, Err(RioConversationError::EmptyContent));
        Ok(())
    }
}
