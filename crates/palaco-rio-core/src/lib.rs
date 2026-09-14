//! RIO interaction and orchestration contracts for PALACO.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use palaco_constitution::{
    ensure_authority_has_provenance, ensure_context_before_action, ensure_decision_has_evidence,
    ensure_execution_is_authorized, AuthorityScope, AuthorizationGrant, ConstitutionalError,
    IdentityHandle, ProvenanceRecord, RevocationRecord, TraceRecord, TraceStatus,
};
use palaco_evidence::EvidenceBundle;
use palaco_knowledge::KnowledgeRecord;
use palaco_trias::GovernanceDecision;

/// Human-to-RIO request entering the constitutional flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioRequest {
    /// Requesting identity.
    pub requester: IdentityHandle,
    /// Surface through which the request arrived.
    pub surface: String,
    /// Human-readable request text.
    pub input: String,
    /// Whether the request has enough context to proceed.
    pub context_ready: bool,
    /// Provenance for the inbound request.
    pub provenance: ProvenanceRecord,
}

/// Prepared answer path for question-and-answer flows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RioAnswerPath {
    /// Retrieved knowledge records available to the answer pipeline.
    pub knowledge: Vec<KnowledgeRecord>,
    /// Evidence selected for the answer.
    pub evidence: Option<EvidenceBundle>,
    /// Governance decision ratifying the answer path.
    pub decision: Option<GovernanceDecision>,
}

/// Prepared action path for execution-bound flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioActionPath {
    /// Authority scope required for the action.
    pub authority: AuthorityScope,
    /// Authorization grant permitting the action.
    pub authorization: Option<AuthorizationGrant>,
    /// Optional revocation that may stop execution.
    pub revocation: Option<RevocationRecord>,
    /// Governance decision supporting the action.
    pub decision: GovernanceDecision,
}

impl RioRequest {
    /// Builds a pending trace record for the request.
    pub fn trace(&self, trace_id: impl Into<String>) -> TraceRecord {
        TraceRecord {
            trace_id: trace_id.into(),
            subject: self.requester.clone(),
            provenance: self.provenance.clone(),
            status: TraceStatus::Pending,
        }
    }
}

/// Validates and prepares an answer flow.
pub fn prepare_answer(
    request: &RioRequest,
    answer_path: &RioAnswerPath,
    trace_id: impl Into<String>,
) -> Result<TraceRecord, ConstitutionalError> {
    ensure_context_before_action(request.context_ready)?;
    ensure_decision_has_evidence(answer_path.evidence.is_some())?;

    if let Some(decision) = &answer_path.decision {
        ensure_authority_has_provenance(&decision.authority, &decision.provenance)?;
    }

    let mut trace = request.trace(trace_id);
    trace.status = TraceStatus::Completed;
    Ok(trace)
}

/// Validates and prepares an execution flow.
pub fn prepare_action(
    request: &RioRequest,
    action_path: &RioActionPath,
    trace_id: impl Into<String>,
) -> Result<TraceRecord, ConstitutionalError> {
    ensure_context_before_action(request.context_ready)?;
    ensure_decision_has_evidence(true)?;
    ensure_authority_has_provenance(
        &action_path.decision.authority,
        &action_path.decision.provenance,
    )?;

    if action_path.authority != action_path.decision.authority {
        return Err(ConstitutionalError::MissingAuthorization);
    }

    ensure_execution_is_authorized(
        &action_path.decision.authority,
        action_path.authorization.as_ref(),
        action_path.revocation.as_ref(),
    )?;

    let mut trace = request.trace(trace_id);
    trace.status = TraceStatus::Completed;
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{LocalResult, TimeZone, Utc};
    use palaco_constitution::{HistoricalClassification, ProvenanceRecord};
    use palaco_events::EventEnvelope;
    use palaco_foundation::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        types::{DecisionContext, TrustLevel, ValidityWindow},
    };
    use palaco_oracle::OracleReport;
    use palaco_types::DomainMarker;

    fn timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Result<chrono::DateTime<Utc>, &'static str> {
        match Utc.with_ymd_and_hms(year, month, day, hour, minute, second) {
            LocalResult::Single(value) => Ok(value),
            LocalResult::Ambiguous(_, _) | LocalResult::None => Err("invalid UTC timestamp"),
        }
    }

    fn context(observed_at: chrono::DateTime<Utc>) -> DecisionContext {
        DecisionContext {
            state: StateSnapshotId::new(),
            policy_version: PolicyVersionId::new(),
            observed_at,
        }
    }

    fn request(context_ready: bool) -> RioRequest {
        RioRequest {
            requester: IdentityHandle {
                subject: "person:1".to_string(),
                surface: "rio-web".to_string(),
            },
            surface: "rio-web".to_string(),
            input: "Can you help?".to_string(),
            context_ready,
            provenance: ProvenanceRecord {
                source: "rio-web".to_string(),
                record_locator: "req-1".to_string(),
            },
        }
    }

    fn evidence() -> Result<EvidenceBundle, &'static str> {
        Ok(EvidenceBundle::new(
            EventEnvelope {
                marker: DomainMarker,
            },
            Evidence::new(
                uuid::Uuid::new_v4(),
                timestamp(2026, 1, 10, 12, 0, 0)?,
                NodeId::new(),
                TrustLevel::High,
                ValidityWindow::new(
                    timestamp(2026, 1, 1, 0, 0, 0)?,
                    timestamp(2026, 1, 31, 23, 59, 59)?,
                ),
            ),
            palaco_evidence::EvidenceCompleteness::Complete,
        ))
    }

    fn decision() -> Result<GovernanceDecision, &'static str> {
        let context = context(timestamp(2026, 1, 15, 12, 0, 0)?);

        Ok(GovernanceDecision::new(
            OracleReport::new(evidence()?, context, palaco_oracle::PlausibleState::Stable),
            context,
            palaco_trias::AuthorizationScope::Execute,
            timestamp(2026, 1, 15, 12, 0, 0)?,
            ValidityWindow::new(
                timestamp(2026, 1, 1, 0, 0, 0)?,
                timestamp(2026, 1, 31, 23, 59, 59)?,
            ),
        ))
    }

    #[test]
    fn answer_flow_requires_context() {
        let result = prepare_answer(&request(false), &RioAnswerPath::default(), "trace-1");
        assert_eq!(result, Err(ConstitutionalError::MissingContext));
    }

    #[test]
    fn answer_flow_requires_evidence() {
        let result = prepare_answer(&request(true), &RioAnswerPath::default(), "trace-1");
        assert_eq!(result, Err(ConstitutionalError::MissingEvidence));
    }

    #[test]
    fn answer_flow_completes_with_evidence() -> Result<(), &'static str> {
        let answer_path = RioAnswerPath {
            knowledge: vec![KnowledgeRecord {
                evidence: evidence()?,
                classification: HistoricalClassification::Specification,
                provenance: ProvenanceRecord {
                    source: "specs/RIO".to_string(),
                    record_locator: "rio-qna".to_string(),
                },
            }],
            evidence: Some(evidence()?),
            decision: Some(decision()?),
        };

        let result = prepare_answer(&request(true), &answer_path, "trace-1");
        assert!(matches!(
            result,
            Ok(TraceRecord {
                status: TraceStatus::Completed,
                ..
            })
        ));

        Ok(())
    }

    #[test]
    fn action_flow_requires_authorization() -> Result<(), &'static str> {
        let action_path = RioActionPath {
            authority: AuthorityScope {
                capability: "palaco.execute".to_string(),
            },
            authorization: None,
            revocation: None,
            decision: decision()?,
        };

        let result = prepare_action(&request(true), &action_path, "trace-1");
        assert_eq!(result, Err(ConstitutionalError::MissingAuthorization));

        Ok(())
    }
}
