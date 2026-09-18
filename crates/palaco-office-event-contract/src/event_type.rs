use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    EmailReceived, EmailUpdated, EmailMoved, EmailFlagged,
    MeetingCreated, MeetingUpdated, MeetingCancelled, MeetingStarted, MeetingEnded,
    DocumentCreated, DocumentUpdated, DocumentMoved,
    TaskCreated, TaskUpdated, TaskCompleted,
    NotionPageCreated, NotionPageUpdated,
    ScheduledEvent, BriefingRequested,
    AuthorizationRequested, AuthorizationGranted, AuthorizationRejected,
    ExecutionStarted, ExecutionCompleted, ExecutionFailed,
    RevokeRequested, Revoked,
}
