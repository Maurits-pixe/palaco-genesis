use crate::errors::ValidationError;

pub trait Identifiable {
    type Id;

    fn id(&self) -> Self::Id;
}

pub trait Validatable {
    fn validate(&self) -> Result<(), ValidationError>;
}
