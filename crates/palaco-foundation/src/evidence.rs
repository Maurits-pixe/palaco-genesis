use crate::{
    identity::NodeId,
    traits::Validatable,
    types::{EvidenceId, Timestamp},
};

pub struct Evidence {
    pub id: EvidenceId,
    pub timestamp: Timestamp,
    pub source: NodeId,
}

impl Validatable for Evidence {
    fn validate(&self) -> Result<(), crate::errors::ValidationError> {
        Ok(())
    }
}
