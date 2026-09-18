use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationState { None, Requested, Granted, Rejected, Revoked, Expired }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState { NotStarted, Started, Completed, Failed, Blocked }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub state: AuthorizationState,
    pub reference: Option<String>,
}

impl Authorization {
    pub fn permits_execution(&self) -> bool { matches!(self.state, AuthorizationState::Granted) }
    pub fn permits_retry(&self) -> bool { self.permits_execution() }
}
