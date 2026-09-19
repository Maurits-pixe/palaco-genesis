#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

/// Canonical monetary lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus { Proposed, Classified, Authorized, Committed, Rejected, Expired, Revoked, Reversed, Suspended }

/// Compliance classification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus { Draft, ClassificationRequired, Review, Authorized, Active, Suspended, Revoked, Archived }

/// PALACO-native instruments remain independent policy domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInstrument { MasterCoin, MissionCoin7 }

impl NativeInstrument {
    pub const fn id(self) -> &'static str { match self { Self::MasterCoin => "MC", Self::MissionCoin7 => "MC7" } }
}

/// Owner-selectable wallet spending profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletProfile { Filantroop, Mescenicas, Misantroop, Blanco }

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
        if self.authorization_ref.is_empty() { return Err("missing authorization"); }
        if self.provenance_ref.is_empty() { return Err("missing provenance"); }
        if self.status != TransactionStatus::Authorized { return Err("operation is not authorized"); }
        Ok(Self { status: TransactionStatus::Committed, ..self })
    }
}


/// Sandbox currency definition with explicit independent policy and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyDefinition {
    pub id: String,
    pub instrument: NativeInstrument,
    pub version: String,
    pub compliance_status: ComplianceStatus,
    pub transferable: bool,
}

impl CurrencyDefinition {
    pub fn sandbox_master_coin() -> Self {
        Self { id: "MC".into(), instrument: NativeInstrument::MasterCoin, version: "0.1.0-sandbox".into(), compliance_status: ComplianceStatus::Draft, transferable: false }
    }
    pub fn sandbox_mission_coin7() -> Self {
        Self { id: "MC7".into(), instrument: NativeInstrument::MissionCoin7, version: "0.1.0-sandbox".into(), compliance_status: ComplianceStatus::Draft, transferable: false }
    }
}

/// A wallet has an owner, profile and currency-scoped account references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wallet {
    pub wallet_id: String,
    pub owner_id: String,
    pub profile: WalletProfile,
    pub account_ids: Vec<String>,
}

/// Reversal preserves the original transaction lineage instead of mutating history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reversal {
    pub reversal_id: String,
    pub original_transaction_id: String,
    pub authorization_ref: String,
    pub provenance_ref: String,
}

impl Reversal {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.original_transaction_id.is_empty() { return Err("missing original transaction"); }
        if self.authorization_ref.is_empty() { return Err("missing authorization"); }
        if self.provenance_ref.is_empty() { return Err("missing provenance"); }
        Ok(())
    }
}

/// A signed, balanced double-entry posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry { pub account_id: String, pub currency_id: String, pub amount: i128 }

/// A transaction is committed only when debits equal credits and its key is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerTransaction {
    pub transaction_id: String,
    pub idempotency_key: String,
    pub currency_id: String,
    pub authorization_ref: String,
    pub provenance_ref: String,
    pub entries: Vec<LedgerEntry>,
}

impl LedgerTransaction {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.transaction_id.is_empty() { return Err("missing transaction id"); }
        if self.idempotency_key.is_empty() { return Err("missing idempotency key"); }
        if self.currency_id.is_empty() { return Err("missing currency"); }
        if self.authorization_ref.is_empty() { return Err("missing authorization"); }
        if self.provenance_ref.is_empty() { return Err("missing provenance"); }
        if self.entries.is_empty() { return Err("transaction has no entries"); }
        let sum = self.entries.iter().try_fold(0i128, |acc, e| acc.checked_add(e.amount).ok_or("amount overflow"))?;
        if sum != 0 { return Err("unbalanced double-entry transaction"); }
        if self.entries.iter().any(|e| e.account_id.is_empty()) { return Err("missing ledger account"); }
        if self.entries.iter().any(|e| e.currency_id != self.currency_id) { return Err("mixed currencies in transaction"); }
        Ok(())
    }
}

/// In-memory sandbox idempotency boundary; no persistence or production custody is implied.
#[derive(Debug, Default)]
pub struct SandboxLedger { committed_keys: Vec<String> }

impl SandboxLedger {
    pub fn commit(&mut self, tx: LedgerTransaction) -> Result<(), &'static str> {
        tx.validate()?;
        if self.committed_keys.iter().any(|k| k == &tx.idempotency_key) { return Err("duplicate idempotency key"); }
        self.committed_keys.push(tx.idempotency_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tx(key: &str) -> LedgerTransaction {
        LedgerTransaction {
            transaction_id: format!("tx-{key}"), idempotency_key: key.into(), currency_id: "MC".into(), authorization_ref: "auth".into(), provenance_ref: "prov".into(),
            entries: vec![LedgerEntry { account_id: "debit".into(), currency_id: "MC".into(), amount: -100 }, LedgerEntry { account_id: "credit".into(), currency_id: "MC".into(), amount: 100 }],
        }
    }
    #[test] fn authorized_operation_can_commit() {
        let operation = MonetaryOperation { transaction_id:"tx-1".into(), currency_id:"MC".into(), currency_version:"0.1".into(), authorization_ref:"auth".into(), provenance_ref:"prov".into(), status:TransactionStatus::Authorized };
        assert_eq!(operation.commit().map(|v|v.status), Ok(TransactionStatus::Committed));
    }
    #[test] fn missing_authorization_fails_closed() {
        let operation = MonetaryOperation { transaction_id:"tx-2".into(), currency_id:"MC7".into(), currency_version:"0.1".into(), authorization_ref:String::new(), provenance_ref:"prov".into(), status:TransactionStatus::Authorized };
        assert_eq!(operation.commit(), Err("missing authorization"));
    }
    #[test] fn double_entry_must_balance() { let mut t=tx("a"); t.entries[1].amount=99; assert_eq!(t.validate(),Err("unbalanced double-entry transaction")); }
    #[test] fn duplicate_idempotency_key_is_rejected() { let mut l=SandboxLedger::default(); assert_eq!(l.commit(tx("same")),Ok(())); assert_eq!(l.commit(tx("same")),Err("duplicate idempotency key")); }
    #[test] fn instruments_remain_distinct() { assert_ne!(NativeInstrument::MasterCoin.id(), NativeInstrument::MissionCoin7.id()); }
}


#[cfg(test)]
mod currency_safety_tests {
    use super::*;

    #[test]
    fn mixed_currencies_are_rejected() {
        let mut t = LedgerTransaction {
            transaction_id: "tx-mixed".into(),
            idempotency_key: "idem-mixed".into(),
            currency_id: "MC".into(),
            authorization_ref: "auth".into(),
            provenance_ref: "prov".into(),
            entries: vec![
                LedgerEntry { account_id: "a".into(), currency_id: "MC".into(), amount: -10 },
                LedgerEntry { account_id: "b".into(), currency_id: "MC7".into(), amount: 10 },
            ],
        };
        assert_eq!(t.validate(), Err("mixed currencies in transaction"));
        t.entries[1].currency_id = "MC".into();
        assert_eq!(t.validate(), Ok(()));
    }

    #[test]
    fn reversal_requires_lineage() {
        let reversal = Reversal { reversal_id: "r1".into(), original_transaction_id: String::new(), authorization_ref: "a".into(), provenance_ref: "p".into() };
        assert_eq!(reversal.validate(), Err("missing original transaction"));
    }
}
