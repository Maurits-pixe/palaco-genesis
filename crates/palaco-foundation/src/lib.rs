#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

pub mod errors;
pub mod evidence;
pub mod identity;
pub mod prelude;
pub mod traits;
pub mod types;

#[cfg(test)]
mod tests {
    use chrono::{LocalResult, TimeZone, Utc};

    use crate::{
        evidence::Evidence,
        identity::{NodeId, PolicyVersionId, StateSnapshotId},
        traits::{CurrentlyAssessable, Revalidatable},
        types::{
            CurrentValidity, DecisionContext, RevalidationOutcome, TrustLevel, ValidityWindow,
        },
    };

    fn timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> chrono::DateTime<Utc> {
        match Utc.with_ymd_and_hms(year, month, day, hour, minute, second) {
            LocalResult::Single(value) => value,
            LocalResult::Ambiguous(_, _) | LocalResult::None => {
                panic!("invalid UTC timestamp")
            }
        }
    }

    #[test]
    fn node_id_is_unique() {
        let a = NodeId::new();
        let b = NodeId::new();

        assert_ne!(a, b);
    }

    #[test]
    fn validity_window_is_active_only_within_bounds() {
        let window = ValidityWindow::new(
            timestamp(2026, 1, 1, 0, 0, 0),
            timestamp(2026, 1, 31, 23, 59, 59),
        );

        assert!(!window.contains(timestamp(2025, 12, 31, 23, 59, 59)));
        assert!(window.contains(timestamp(2026, 1, 15, 12, 0, 0)));
        assert!(!window.contains(timestamp(2026, 2, 1, 0, 0, 0)));
    }

    #[test]
    fn evidence_revalidation_confirms_when_context_is_current_and_trusted() {
        let window = ValidityWindow::new(
            timestamp(2026, 1, 1, 0, 0, 0),
            timestamp(2026, 1, 31, 23, 59, 59),
        );
        let evidence = Evidence::new(
            uuid::Uuid::new_v4(),
            timestamp(2026, 1, 10, 12, 0, 0),
            NodeId::new(),
            TrustLevel::High,
            window,
        );
        let context = DecisionContext {
            state: StateSnapshotId::new(),
            policy_version: PolicyVersionId::new(),
            observed_at: timestamp(2026, 1, 15, 12, 0, 0),
        };

        assert_eq!(
            evidence.current_validity(context.observed_at),
            CurrentValidity::Valid
        );
        assert_eq!(
            evidence.revalidate(&context),
            Ok(RevalidationOutcome::Confirmed)
        );
    }

    #[test]
    fn evidence_revalidation_escalates_on_low_trust() {
        let evidence = Evidence::new(
            uuid::Uuid::new_v4(),
            timestamp(2026, 1, 10, 12, 0, 0),
            NodeId::new(),
            TrustLevel::Low,
            ValidityWindow::new(
                timestamp(2026, 1, 1, 0, 0, 0),
                timestamp(2026, 1, 31, 23, 59, 59),
            ),
        );
        let context = DecisionContext {
            state: StateSnapshotId::new(),
            policy_version: PolicyVersionId::new(),
            observed_at: timestamp(2026, 1, 15, 12, 0, 0),
        };

        assert_eq!(
            evidence.current_validity(context.observed_at),
            CurrentValidity::InsufficientEvidence
        );
        assert!(evidence.revalidate(&context).is_err());
    }
}
