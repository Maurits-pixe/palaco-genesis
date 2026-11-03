//! Trusted identity provider boundary for ORCHEASTRA.
//!
//! No provider is configured by this crate. The default verifier fails closed.
//! An identity assessment never grants runtime execution authority.

use palaco_constitution::IdentityHandle;

/// Opaque reference to authentication evidence, not a credential or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEvidenceRequest {
    /// Actor whose identity must be checked.
    pub actor: IdentityHandle,
    /// Non-secret handle used to locate the credential at the trusted provider.
    pub credential_ref: String,
    /// Expected issuer identifier, set by trusted server configuration.
    pub expected_issuer: String,
    /// Expected audience, set by trusted server configuration.
    pub expected_audience: String,
}

/// Result of identity evidence assessment only; never execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityAssessment {
    /// Verified by a separately audited and configured trusted adapter.
    Verified,
    /// A mandatory proof condition demonstrably failed.
    Denied,
    /// Required provider, configuration, or evidence is missing.
    #[default]
    Hold,
    /// Present evidence is contradictory or unverifiable.
    Inconclusive,
}

/// Boundary implemented only by an independently reviewed trusted adapter.
///
/// Merely implementing this trait or returning `Verified` does not establish
/// trust. The adapter's deployment, issuer policy, signature verification,
/// trusted time, revocation source and provenance must be independently
/// authorized before its output is consumed.
pub trait TrustedIdentityVerifier {
    /// Assesses identity evidence, without issuing execution authorization.
    fn assess(&self, request: &IdentityEvidenceRequest) -> IdentityAssessment;
}

/// Performs fail-closed structural checks before consulting an adapter.
///
/// This function reports identity evidence assessment only. A `Verified`
/// result does not authorize an action and cannot substitute for independent
/// trust configuration, revocation checks or a TRIAS decision.
pub fn assess_identity_evidence(
    verifier: &impl TrustedIdentityVerifier,
    request: &IdentityEvidenceRequest,
) -> IdentityAssessment {
    if request.actor.subject.is_empty()
        || request.actor.surface.is_empty()
        || request.credential_ref.is_empty()
        || request.expected_issuer.is_empty()
        || request.expected_audience.is_empty()
    {
        return IdentityAssessment::Hold;
    }
    verifier.assess(request)
}

/// Safe default until a genuine trusted provider is selected and configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredIdentityVerifier;

impl TrustedIdentityVerifier for UnconfiguredIdentityVerifier {
    fn assess(&self, _request: &IdentityEvidenceRequest) -> IdentityAssessment {
        IdentityAssessment::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assess_identity_evidence, IdentityAssessment, IdentityEvidenceRequest,
        TrustedIdentityVerifier, UnconfiguredIdentityVerifier,
    };
    use palaco_constitution::IdentityHandle;

    fn request() -> IdentityEvidenceRequest {
        IdentityEvidenceRequest {
            actor: IdentityHandle {
                subject: "actor-1".to_string(),
                surface: "palaco-citadel".to_string(),
            },
            credential_ref: "opaque-ref-1".to_string(),
            expected_issuer: "configured-issuer".to_string(),
            expected_audience: "palaco-citadel".to_string(),
        }
    }

    struct TestVerifier;

    impl TrustedIdentityVerifier for TestVerifier {
        fn assess(&self, _request: &IdentityEvidenceRequest) -> IdentityAssessment {
            IdentityAssessment::Verified
        }
    }

    #[test]
    fn incomplete_actor_is_held_before_adapter() {
        let mut input = request();
        input.actor.subject.clear();
        assert_eq!(assess_identity_evidence(&TestVerifier, &input), IdentityAssessment::Hold);
    }

    #[test]
    fn missing_credential_reference_is_held_before_adapter() {
        let mut input = request();
        input.credential_ref.clear();
        assert_eq!(assess_identity_evidence(&TestVerifier, &input), IdentityAssessment::Hold);
    }

    #[test]
    fn missing_issuer_is_held_before_adapter() {
        let mut input = request();
        input.expected_issuer.clear();
        assert_eq!(assess_identity_evidence(&TestVerifier, &input), IdentityAssessment::Hold);
    }

    #[test]
    fn missing_audience_is_held_before_adapter() {
        let mut input = request();
        input.expected_audience.clear();
        assert_eq!(assess_identity_evidence(&TestVerifier, &input), IdentityAssessment::Hold);
    }

    #[test]
    fn unconfigured_provider_never_verifies_identity() {
        let verifier = UnconfiguredIdentityVerifier;
        assert_eq!(verifier.assess(&request()), IdentityAssessment::Hold);
    }

    #[test]
    fn missing_reference_does_not_bypass_default_hold() {
        let verifier = UnconfiguredIdentityVerifier;
        let mut input = request();
        input.credential_ref.clear();
        assert_eq!(verifier.assess(&input), IdentityAssessment::Hold);
    }

    #[test]
    fn changed_actor_does_not_bypass_default_hold() {
        let verifier = UnconfiguredIdentityVerifier;
        let mut input = request();
        input.actor.subject = "substituted".to_string();
        assert_eq!(verifier.assess(&input), IdentityAssessment::Hold);
    }

    #[test]
    fn missing_trust_configuration_does_not_bypass_default_hold() {
        let verifier = UnconfiguredIdentityVerifier;
        let mut input = request();
        input.expected_issuer.clear();
        input.expected_audience.clear();
        assert_eq!(verifier.assess(&input), IdentityAssessment::Hold);
    }
}
