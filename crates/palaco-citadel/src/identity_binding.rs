//! Identity-to-grant binding checks for the Citadel boundary.
//!
//! This contract checks declared identity consistency. It does not authenticate
//! an actor, verify signatures, check revocation, or authorize execution.

use palaco_constitution::{AuthorityScope, AuthorizationGrant, IdentityHandle};
use palaco_foundation::errors::ValidationError;

/// Checks that a declared actor is exactly bound to a scoped grant.
///
/// A successful result is only a consistency finding. A separate trusted
/// authentication, temporal, revocation and governance gate remains required.
pub fn validate_actor_binding(
    actor: &IdentityHandle,
    grant: &AuthorizationGrant,
    requested_scope: &AuthorityScope,
) -> Result<(), ValidationError> {
    if actor.subject.is_empty() || actor.surface.is_empty() {
        return Err(ValidationError::Message {
            message: "actor identity is incomplete".to_string(),
        });
    }
    if grant.granted_to.subject.is_empty() || grant.granted_to.surface.is_empty() {
        return Err(ValidationError::Message {
            message: "grant subject identity is incomplete".to_string(),
        });
    }
    if grant.granted_to != *actor {
        return Err(ValidationError::Message {
            message: "actor does not match grant subject".to_string(),
        });
    }
    if requested_scope.capability.is_empty() || grant.scope != *requested_scope {
        return Err(ValidationError::Message {
            message: "requested scope does not match grant".to_string(),
        });
    }
    if grant.authorization_id.is_empty()
        || grant.provenance.source.is_empty()
        || grant.provenance.record_locator.is_empty()
    {
        return Err(ValidationError::Message {
            message: "grant authorization or provenance is incomplete".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_actor_binding;
    use palaco_constitution::{
        AuthorityScope, AuthorizationGrant, IdentityHandle, ProvenanceRecord,
    };

    fn fixture() -> (IdentityHandle, AuthorizationGrant, AuthorityScope) {
        let actor = IdentityHandle {
            subject: "actor-1".to_string(),
            surface: "palaco-citadel".to_string(),
        };
        let scope = AuthorityScope {
            capability: "palaco.execute".to_string(),
        };
        let grant = AuthorizationGrant {
            authorization_id: "grant-1".to_string(),
            scope: scope.clone(),
            granted_to: actor.clone(),
            provenance: ProvenanceRecord {
                source: "palaco-trias".to_string(),
                record_locator: "decision:1".to_string(),
            },
        };
        (actor, grant, scope)
    }

    #[test]
    fn matching_actor_and_grant_are_consistent() {
        let (actor, grant, scope) = fixture();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_ok());
    }

    #[test]
    fn missing_actor_identity_is_rejected() {
        let (mut actor, grant, scope) = fixture();
        actor.subject.clear();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn default_grant_identity_is_rejected() {
        let (actor, mut grant, scope) = fixture();
        grant.granted_to = IdentityHandle::default();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn substituted_actor_is_rejected() {
        let (mut actor, grant, scope) = fixture();
        actor.subject = "another-actor".to_string();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn changed_surface_is_rejected() {
        let (mut actor, grant, scope) = fixture();
        actor.surface = "another-surface".to_string();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn scope_escalation_is_rejected() {
        let (actor, grant, mut scope) = fixture();
        scope.capability = "palaco.admin".to_string();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn missing_grant_authorization_id_is_rejected() {
        let (actor, mut grant, scope) = fixture();
        grant.authorization_id.clear();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn missing_provenance_source_is_rejected() {
        let (actor, mut grant, scope) = fixture();
        grant.provenance.source.clear();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn empty_requested_scope_is_rejected() {
        let (actor, grant, mut scope) = fixture();
        scope.capability.clear();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }

    #[test]
    fn missing_provenance_is_rejected() {
        let (actor, mut grant, scope) = fixture();
        grant.provenance.record_locator.clear();
        assert!(validate_actor_binding(&actor, &grant, &scope).is_err());
    }
}
