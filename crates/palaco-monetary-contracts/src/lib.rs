#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/// Canonical monetary lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Proposed,
    Classified,
    Authorized,
    Committed,
    Rejected,
    Expired,
    Revoked,
    Reversed,
    Suspended,
}

/// Compliance classification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Draft,
    ClassificationRequired,
    Review,
    Authorized,
    Active,
    Suspended,
    Revoked,
    Archived,
}

/// PALACO-native instruments remain independent policy domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInstrument {
    MasterCoin,
    MissionCoin7,
}

/// Owner-selectable wallet spending profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletProfile {
    Filantroop,
    Mescenicas,
    Misantroop,
    Blanco,
}

/// A monetary operation must carry authorization and provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryOperation {
    pub transaction_id: String,
    pub currency_id: String,
    pub currency_version: String,
    pub authorization_ref: String,
    pub provenance_ref: String,
    pub status: TransactionStatus,
}

impl MonetaryOperation {
    pub fn commit(self) -> Result<Self, &'static str> {
        if self.authorization_ref.is_empty() {
            return Err("missing authorization");
        }
        if self.provenance_ref.is_empty() {
            return Err("missing provenance");
        }
        if self.status != TransactionStatus::Authorized {
            return Err("operation is not authorized");
        }
        Ok(Self {
            status: TransactionStatus::Committed,
            ..self
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_operation_can_commit() {
        let operation = MonetaryOperation {
            transaction_id: "tx-1".into(),
            currency_id: "MC".into(),
            currency_version: "0.1".into(),
            authorization_ref: "auth-1".into(),
            provenance_ref: "prov-1".into(),
            status: TransactionStatus::Authorized,
        };

        assert_eq!(
            operation.commit().map(|value| value.status),
            Ok(TransactionStatus::Committed)
        );
    }

    #[test]
    fn missing_authorization_fails_closed() {
        let operation = MonetaryOperation {
            transaction_id: "tx-2".into(),
            currency_id: "MC7".into(),
            currency_version: "0.1".into(),
            authorization_ref: String::new(),
            provenance_ref: "prov-2".into(),
            status: TransactionStatus::Authorized,
        };

        assert_eq!(operation.commit(), Err("missing authorization"));
    }
}
