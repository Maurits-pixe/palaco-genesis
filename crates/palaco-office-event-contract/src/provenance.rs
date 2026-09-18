use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_ref: String,
    pub parent_event_id: Option<String>,
    pub source_hash: Option<String>,
}

impl Provenance {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.source_ref.trim().is_empty() { return Err("missing provenance source_ref"); }
        Ok(())
    }
}
