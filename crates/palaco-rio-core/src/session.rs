//! RIO session lifecycle primitives.

use chrono::{DateTime, Utc};
use palaco_constitution::{IdentityHandle, ProvenanceRecord};
use uuid::Uuid;

/// Stable identifier for a RIO conversation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RioSessionId(Uuid);

impl RioSessionId {
    /// Creates a new session identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RioSessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle state of a RIO session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioSessionState {
    /// Session is accepting communication.
    Active,
    /// Session has been explicitly revoked and cannot continue.
    Revoked,
}

/// Runtime session binding an identity to one RIO surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioSession {
    /// Stable session identifier.
    pub id: RioSessionId,
    /// Identity bound to the session.
    pub identity: IdentityHandle,
    /// Surface on which the session was established.
    pub surface: String,
    /// Session lifecycle state.
    pub state: RioSessionState,
    /// Time at which the session was created.
    pub created_at: DateTime<Utc>,
    /// Last activity observed for the session.
    pub last_activity_at: DateTime<Utc>,
    /// Provenance for session establishment.
    pub provenance: ProvenanceRecord,
}

impl RioSession {
    /// Opens a new active session.
    pub fn open(
        identity: IdentityHandle,
        surface: impl Into<String>,
        provenance: ProvenanceRecord,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: RioSessionId::new(),
            identity,
            surface: surface.into(),
            state: RioSessionState::Active,
            created_at: now,
            last_activity_at: now,
            provenance,
        }
    }

    /// Returns true only while the session remains active.
    pub fn is_active(&self) -> bool {
        self.state == RioSessionState::Active
    }

    /// Records activity without changing authorization.
    pub fn touch(&mut self, now: DateTime<Utc>) -> bool {
        if !self.is_active() {
            return false;
        }
        self.last_activity_at = now;
        true
    }

    /// Revokes the session. Revocation is terminal for this session instance.
    pub fn revoke(&mut self) {
        self.state = RioSessionState::Revoked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> IdentityHandle {
        IdentityHandle {
            subject: "person:test".to_string(),
            surface: "rio-web".to_string(),
        }
    }

    fn provenance() -> ProvenanceRecord {
        ProvenanceRecord {
            source: "rio-web".to_string(),
            record_locator: "session-test".to_string(),
        }
    }

    #[test]
    fn session_opens_active() {
        let now = Utc::now();
        let session = RioSession::open(identity(), "rio-web", provenance(), now);
        assert!(session.is_active());
        assert_eq!(session.created_at, now);
        assert_eq!(session.last_activity_at, now);
    }

    #[test]
    fn revoked_session_cannot_be_touched() {
        let now = Utc::now();
        let mut session = RioSession::open(identity(), "rio-web", provenance(), now);
        session.revoke();
        assert!(!session.is_active());
        assert!(!session.touch(now));
        assert_eq!(session.state, RioSessionState::Revoked);
    }

    #[test]
    fn touch_updates_active_session() {
        let created = Utc::now();
        let later = created + chrono::Duration::seconds(5);
        let mut session = RioSession::open(identity(), "rio-web", provenance(), created);
        assert!(session.touch(later));
        assert_eq!(session.last_activity_at, later);
    }
}
