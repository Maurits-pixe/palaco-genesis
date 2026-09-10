use crate::{
    errors::{RevalidationError, ValidationError},
    types::{CurrentValidity, RevalidationOutcome, Timestamp},
};

pub trait Identifiable {
    type Id;

    fn id(&self) -> Self::Id;
}

pub trait Validatable {
    fn validate(&self) -> Result<(), ValidationError>;
}

pub trait CurrentlyAssessable {
    fn current_validity(&self, at: Timestamp) -> CurrentValidity;
}

pub trait Revalidatable {
    type Context;

    fn revalidate(&self, context: &Self::Context)
        -> Result<RevalidationOutcome, RevalidationError>;
}

pub trait FailClosed {
    type Output;

    fn fail_closed(&self) -> Self::Output;
}
