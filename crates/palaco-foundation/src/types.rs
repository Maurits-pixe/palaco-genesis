use crate::identity::{PolicyVersionId, StateSnapshotId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EvidenceId = Uuid;
pub type Timestamp = DateTime<Utc>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityWindow {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl ValidityWindow {
    #[must_use]
    pub fn new(not_before: Timestamp, not_after: Timestamp) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    #[must_use]
    pub fn contains(&self, timestamp: Timestamp) -> bool {
        self.not_before <= timestamp && timestamp <= self.not_after
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurrentValidity {
    Pending,
    Valid,
    Expired,
    Revoked,
    InsufficientEvidence,
    SafeStateRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevalidationOutcome {
    Confirmed,
    Escalated,
    Revoked,
    SafeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionContext {
    pub state: StateSnapshotId,
    pub policy_version: PolicyVersionId,
    pub observed_at: Timestamp,
}
