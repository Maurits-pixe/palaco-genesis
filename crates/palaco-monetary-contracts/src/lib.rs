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


/// Registry of explicitly registered currencies. In-memory sandbox only.
#[derive(Debug, Default)]
pub struct CurrencyRegistry {
    currencies: Vec<CurrencyDefinition>,
}

impl CurrencyRegistry {
    /// Register a currency exactly once.
    pub fn register(&mut self, currency: CurrencyDefinition) -> Result<(), &'static str> {
        if currency.id.is_empty() { return Err("missing currency id"); }
        if self.currencies.iter().any(|c| c.id == currency.id) {
            return Err("duplicate currency registration");
        }
        self.currencies.push(currency);
        Ok(())
    }

    /// Activate a registered currency only with explicit authorization and provenance.
    pub fn activate(&mut self, currency_id: &str, authorization_ref: &str, provenance_ref: &str) -> Result<(), &'static str> {
        if authorization_ref.is_empty() { return Err("missing authorization"); }
        if provenance_ref.is_empty() { return Err("missing provenance"); }
        let currency = self.currencies.iter_mut().find(|c| c.id == currency_id).ok_or("currency not registered")?;
        if matches!(currency.compliance_status, ComplianceStatus::Suspended | ComplianceStatus::Revoked | ComplianceStatus::Archived) {
            return Err("currency cannot be activated");
        }
        currency.compliance_status = ComplianceStatus::Active;
        Ok(())
    }

    /// Resolve a currency only when it is active.
    pub fn active(&self, currency_id: &str) -> Result<&CurrencyDefinition, &'static str> {
        let currency = self.currencies.iter().find(|c| c.id == currency_id).ok_or("currency not registered")?;
        if currency.compliance_status != ComplianceStatus::Active {
            return Err("currency is not active");
        }
        Ok(currency)
    }

    pub fn get(&self, currency_id: &str) -> Option<&CurrencyDefinition> {
        self.currencies.iter().find(|c| c.id == currency_id)
    }
}

/// A currency-scoped ledger account belongs to one wallet owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAccount {
    pub account_id: String,
    pub wallet_id: String,
    pub owner_id: String,
    pub currency_id: String,
}

/// In-memory wallet/account registry for the sandbox.
#[derive(Debug, Default)]
pub struct WalletRegistry {
    wallets: Vec<Wallet>,
    accounts: Vec<WalletAccount>,
    profile_history: Vec<(String, WalletProfile)>,
}

impl WalletRegistry {
    pub fn create_wallet(&mut self, wallet: Wallet) -> Result<(), &'static str> {
        if wallet.wallet_id.is_empty() { return Err("missing wallet id"); }
        if wallet.owner_id.is_empty() { return Err("missing owner id"); }
        if self.wallets.iter().any(|w| w.wallet_id == wallet.wallet_id) {
            return Err("duplicate wallet");
        }
        self.profile_history.push((wallet.wallet_id.clone(), wallet.profile));
        self.wallets.push(wallet);
        Ok(())
    }

    /// Profile changes are append-traced; the previous profile is never overwritten in history.
    pub fn change_profile(&mut self, wallet_id: &str, profile: WalletProfile) -> Result<(), &'static str> {
        let wallet = self.wallets.iter_mut().find(|w| w.wallet_id == wallet_id).ok_or("wallet not found")?;
        wallet.profile = profile;
        self.profile_history.push((wallet_id.into(), profile));
        Ok(())
    }

    /// Create an account only for a registered wallet and an active currency.
    pub fn add_account(&mut self, account: WalletAccount, currencies: &CurrencyRegistry) -> Result<(), &'static str> {
        if account.account_id.is_empty() { return Err("missing account id"); }
        if account.wallet_id.is_empty() || account.owner_id.is_empty() { return Err("missing wallet ownership"); }
        if self.accounts.iter().any(|a| a.account_id == account.account_id) {
            return Err("duplicate account");
        }
        let wallet = self.wallets.iter().find(|w| w.wallet_id == account.wallet_id).ok_or("wallet not found")?;
        if wallet.owner_id != account.owner_id { return Err("wallet owner mismatch"); }
        currencies.active(&account.currency_id)?;
        self.accounts.push(account);
        Ok(())
    }

    pub fn profile_history(&self, wallet_id: &str) -> impl Iterator<Item = WalletProfile> + '_ {
        self.profile_history.iter().filter_map(move |(id, profile)| (id == wallet_id).then_some(*profile))
    }
}

/// Controlled sandbox seed: creates a balanced ledger transaction; it never mutates a balance directly.
pub fn sandbox_seed(
    ledger: &mut SandboxLedger,
    currencies: &CurrencyRegistry,
    account_id: &str,
    treasury_account_id: &str,
    currency_id: &str,
    amount: i128,
    authorization_ref: &str,
    provenance_ref: &str,
    idempotency_key: &str,
) -> Result<(), &'static str> {
    if amount <= 0 { return Err("seed amount must be positive"); }
    currencies.active(currency_id)?;
    let tx = LedgerTransaction {
        transaction_id: format!("seed-{idempotency_key}"),
        idempotency_key: idempotency_key.into(),
        currency_id: currency_id.into(),
        authorization_ref: authorization_ref.into(),
        provenance_ref: provenance_ref.into(),
        entries: vec![
            LedgerEntry { account_id: treasury_account_id.into(), currency_id: currency_id.into(), amount: -amount },
            LedgerEntry { account_id: account_id.into(), currency_id: currency_id.into(), amount },
        ],
    };
    ledger.commit(tx)
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn active_registry() -> CurrencyRegistry {
        let mut registry = CurrencyRegistry::default();
        assert!(registry.register(CurrencyDefinition::sandbox_master_coin()).is_ok());
        assert!(registry.activate("MC", "auth", "prov").is_ok());;
        registry
    }

    #[test]
    fn duplicate_currency_registration_is_rejected() {
        let mut registry = CurrencyRegistry::default();
        assert_eq!(registry.register(CurrencyDefinition::sandbox_master_coin()), Ok(()));
        assert_eq!(registry.register(CurrencyDefinition::sandbox_master_coin()), Err("duplicate currency registration"));
    }

    #[test]
    fn unauthorized_activation_fails_closed() {
        let mut registry = CurrencyRegistry::default();
        registry.register(CurrencyDefinition::sandbox_master_coin());;
        assert_eq!(registry.activate("MC", "", "prov"), Err("missing authorization"));
        assert_eq!(registry.get("MC").map(|c| c.compliance_status), Some(ComplianceStatus::Draft));
    }

    #[test]
    fn suspended_currency_cannot_activate() {
        let mut registry = active_registry();
        let currency = registry.currencies.iter_mut().find(|c| c.id == "MC");
        if let Some(c) = currency { c.compliance_status = ComplianceStatus::Suspended; }
        assert_eq!(registry.activate("MC", "auth", "prov"), Err("currency cannot be activated"));
    }

    #[test]
    fn wallet_profile_change_is_traceable() {
        let mut wallets = WalletRegistry::default();
        assert!(wallets.create_wallet(Wallet { wallet_id: "w1".into(), owner_id: "c1".into(), profile: WalletProfile::Blanco, account_ids: Vec::new() }).is_ok());
        assert!(wallets.change_profile("w1", WalletProfile::Filantroop).is_ok());
        let history: Vec<_> = wallets.profile_history("w1").collect();
        assert_eq!(history, vec![WalletProfile::Blanco, WalletProfile::Filantroop]);
    }

    #[test]
    fn mc_and_mc7_remain_separate_accounts() {
        let mut currencies = CurrencyRegistry::default();
        currencies.register(CurrencyDefinition::sandbox_master_coin());;
        currencies.register(CurrencyDefinition::sandbox_mission_coin7());;
        currencies.activate("MC", "auth-mc", "prov-mc");;
        currencies.activate("MC7", "auth-mc7", "prov-mc7");;

        let mut wallets = WalletRegistry::default();
        wallets.create_wallet(Wallet { wallet_id: "w1".into(), owner_id: "c1".into(), profile: WalletProfile::Blanco, account_ids: Vec::new() });;
        assert!(wallets.add_account(WalletAccount { account_id: "a-mc".into(), wallet_id: "w1".into(), owner_id: "c1".into(), currency_id: "MC".into() }, &currencies).is_ok());
        assert!(wallets.add_account(WalletAccount { account_id: "a-mc7".into(), wallet_id: "w1".into(), owner_id: "c1".into(), currency_id: "MC7".into() }, &currencies).is_ok());
        assert_eq!(wallets.accounts.len(), 2);
        assert_ne!(wallets.accounts[0].currency_id, wallets.accounts[1].currency_id);
    }

    #[test]
    fn sandbox_seed_posts_ledger_entries_instead_of_mutating_balance() {
        let currencies = active_registry();
        let mut ledger = SandboxLedger::default();
        assert_eq!(sandbox_seed(&mut ledger, &currencies, "a1", "treasury", "MC", 25, "auth", "prov", "seed-1"), Ok(()));
        assert_eq!(sandbox_seed(&mut ledger, &currencies, "a1", "treasury", "MC", 25, "auth", "prov", "seed-1"), Err("duplicate idempotency key"));
    }
}

/// Canonical audit/event vocabulary for the monetary sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonetaryEvent {
    CurrencyRegistered { currency_id: String, version: String, provenance_ref: String },
    CurrencyActivated { currency_id: String, authorization_ref: String, provenance_ref: String },
    WalletCreated { wallet_id: String, owner_id: String, profile: WalletProfile },
    WalletProfileChanged { wallet_id: String, profile: WalletProfile },
    AccountCreated { account_id: String, wallet_id: String, currency_id: String },
    RewardGranted { reward_id: String, account_id: String, currency_id: String, amount: i128, rule_ref: String },
    LedgerCommitted { transaction_id: String, currency_id: String, idempotency_key: String },
    TransactionReversed { reversal_id: String, original_transaction_id: String },
}

impl MonetaryEvent {
    /// Every event exposes a stable domain name for audit routing.
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::CurrencyRegistered { .. } => "currency.registered",
            Self::CurrencyActivated { .. } => "currency.activated",
            Self::WalletCreated { .. } => "wallet.created",
            Self::WalletProfileChanged { .. } => "wallet.profile_changed",
            Self::AccountCreated { .. } => "account.created",
            Self::RewardGranted { .. } => "reward.granted",
            Self::LedgerCommitted { .. } => "ledger.committed",
            Self::TransactionReversed { .. } => "transaction.reversed",
        }
    }
}

/// Reward issuance is represented as a ledger intent; it never writes a balance directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardGrant {
    pub reward_id: String,
    pub account_id: String,
    pub currency_id: String,
    pub amount: i128,
    pub rule_ref: String,
    pub authorization_ref: String,
    pub provenance_ref: String,
}

impl RewardGrant {
    pub fn validate(&self, currencies: &CurrencyRegistry) -> Result<(), &'static str> {
        if self.reward_id.is_empty() { return Err("missing reward id"); }
        if self.account_id.is_empty() { return Err("missing reward account"); }
        if self.rule_ref.is_empty() { return Err("missing reward rule"); }
        if self.authorization_ref.is_empty() { return Err("missing authorization"); }
        if self.provenance_ref.is_empty() { return Err("missing provenance"); }
        if self.amount <= 0 { return Err("reward amount must be positive"); }
        let currency = currencies.active(&self.currency_id)?;
        if currency.transferable { return Err("sandbox reward currency must not be transferable"); }
        Ok(())
    }

    pub fn event(&self) -> MonetaryEvent {
        MonetaryEvent::RewardGranted {
            reward_id: self.reward_id.clone(),
            account_id: self.account_id.clone(),
            currency_id: self.currency_id.clone(),
            amount: self.amount,
            rule_ref: self.rule_ref.clone(),
        }
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

    #[test]
    fn reward_requires_active_non_transferable_currency() {
        let mut currencies = CurrencyRegistry::default();
        let mut mc = CurrencyDefinition::sandbox_master_coin();
        mc.transferable = false;
        assert!(currencies.register(mc).is_ok());
        assert!(currencies.activate("MC", "auth", "prov").is_ok());

        let reward = RewardGrant {
            reward_id: "reward-1".into(),
            account_id: "account-1".into(),
            currency_id: "MC".into(),
            amount: 10,
            rule_ref: "rule-1".into(),
            authorization_ref: "auth".into(),
            provenance_ref: "prov".into(),
        };
        assert!(reward.validate(&currencies).is_ok());
        assert_eq!(reward.event().event_type(), "reward.granted");
    }

    #[test]
    fn reward_rejects_transferable_currency() {
        let mut currencies = CurrencyRegistry::default();
        let mut mc = CurrencyDefinition::sandbox_master_coin();
        mc.transferable = true;
        assert!(currencies.register(mc).is_ok());
        assert!(currencies.activate("MC", "auth", "prov").is_ok());
        let reward = RewardGrant {
            reward_id: "reward-2".into(), account_id: "account-1".into(), currency_id: "MC".into(),
            amount: 10, rule_ref: "rule-1".into(), authorization_ref: "auth".into(), provenance_ref: "prov".into(),
        };
        assert_eq!(reward.validate(&currencies), Err("sandbox reward currency must not be transferable"));
    }
}


/// Immutable-in-use, append-only event journal for the monetary sandbox.
///
/// The journal records what happened; it never grants authority. Authorization and
/// provenance are captured on every record so an event cannot be detached from its
/// constitutional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryJournalEntry {
    pub sequence: u64,
    pub event_id: String,
    pub event_type: String,
    pub timestamp_utc: String,
    pub aggregate_ref: String,
    pub authorization_ref: String,
    pub provenance_ref: String,
    pub event: MonetaryEvent,
}

/// Append-only sandbox journal. Its entries are private: the public API exposes
/// read-only iterators and trace queries, never mutation or deletion.
#[derive(Debug, Default)]
pub struct MonetaryJournal {
    entries: Vec<MonetaryJournalEntry>,
}

impl MonetaryJournal {
    pub fn append(
        &mut self,
        event_id: &str,
        timestamp_utc: &str,
        aggregate_ref: &str,
        authorization_ref: &str,
        provenance_ref: &str,
        event: MonetaryEvent,
    ) -> Result<u64, &'static str> {
        if event_id.is_empty() { return Err("missing event id"); }
        if timestamp_utc.is_empty() { return Err("missing timestamp"); }
        if aggregate_ref.is_empty() { return Err("missing aggregate reference"); }
        if authorization_ref.is_empty() { return Err("missing authorization"); }
        if provenance_ref.is_empty() { return Err("missing provenance"); }
        if self.entries.iter().any(|entry| entry.event_id == event_id) {
            return Err("duplicate event id");
        }
        let sequence = u64::try_from(self.entries.len()).map_err(|_| "journal sequence overflow")?
            .checked_add(1).ok_or("journal sequence overflow")?;
        self.entries.push(MonetaryJournalEntry {
            sequence,
            event_id: event_id.into(),
            event_type: event.event_type().into(),
            timestamp_utc: timestamp_utc.into(),
            aggregate_ref: aggregate_ref.into(),
            authorization_ref: authorization_ref.into(),
            provenance_ref: provenance_ref.into(),
            event,
        });
        Ok(sequence)
    }

    pub fn entries(&self) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter()
    }

    pub fn trace_transaction(&self, transaction_id: &str) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter().filter(move |entry| match &entry.event {
            MonetaryEvent::LedgerCommitted { transaction_id: id, .. } |
            MonetaryEvent::TransactionReversed { original_transaction_id: id, .. } => id == transaction_id,
            _ => entry.aggregate_ref == transaction_id,
        })
    }

    /// Record one typed event after its authorization/provenance context exists.
    pub fn record(&mut self, event_id: &str, timestamp_utc: &str, aggregate_ref: &str, authorization_ref: &str, provenance_ref: &str, event: MonetaryEvent) -> Result<u64, &'static str> {
        self.append(event_id, timestamp_utc, aggregate_ref, authorization_ref, provenance_ref, event)
    }

    pub fn trace_wallet(&self, wallet_id: &str) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter().filter(move |entry| match &entry.event {
            MonetaryEvent::WalletCreated { wallet_id: id, .. } |
            MonetaryEvent::WalletProfileChanged { wallet_id: id, .. } => id == wallet_id,
            MonetaryEvent::AccountCreated { wallet_id: id, .. } => id == wallet_id,
            _ => entry.aggregate_ref == wallet_id,
        })
    }

    pub fn trace_account(&self, account_id: &str) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter().filter(move |entry| match &entry.event {
            MonetaryEvent::AccountCreated { account_id: id, .. } |
            MonetaryEvent::RewardGranted { account_id: id, .. } => id == account_id,
            _ => entry.aggregate_ref == account_id,
        })
    }

    pub fn trace_reward(&self, reward_id: &str) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter().filter(move |entry| match &entry.event {
            MonetaryEvent::RewardGranted { reward_id: id, .. } => id == reward_id,
            _ => entry.aggregate_ref == reward_id,
        })
    }

    pub fn trace_currency(&self, currency_id: &str) -> impl Iterator<Item = &MonetaryJournalEntry> {
        self.entries.iter().filter(move |entry| match &entry.event {
            MonetaryEvent::CurrencyRegistered { currency_id: id, .. } |
            MonetaryEvent::CurrencyActivated { currency_id: id, .. } |
            MonetaryEvent::RewardGranted { currency_id: id, .. } |
            MonetaryEvent::LedgerCommitted { currency_id: id, .. } |
            MonetaryEvent::AccountCreated { currency_id: id, .. } => id == currency_id,
            _ => entry.aggregate_ref == currency_id,
        })
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    fn journal_event(id: &str) -> MonetaryEvent {
        MonetaryEvent::LedgerCommitted {
            transaction_id: id.into(),
            currency_id: "MC".into(),
            idempotency_key: format!("idem-{id}"),
        }
    }

    #[test]
    fn journal_sequence_is_monotonic_and_traceable() {
        let mut journal = MonetaryJournal::default();
        assert_eq!(journal.append("e1", "2026-09-19T06:00:00Z", "tx-1", "auth", "prov", journal_event("tx-1")), Ok(1));
        assert_eq!(journal.append("e2", "2026-09-19T06:01:00Z", "tx-1", "auth", "prov", journal_event("tx-2")), Ok(2));
        let trace: Vec<_> = journal.trace_transaction("tx-1").collect();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].sequence, 1);
    }

    #[test]
    fn duplicate_event_id_is_rejected() {
        let mut journal = MonetaryJournal::default();
        assert!(journal.append("e1", "2026-09-19T06:00:00Z", "tx-1", "auth", "prov", journal_event("tx-1")).is_ok());
        assert_eq!(journal.append("e1", "2026-09-19T06:01:00Z", "tx-1", "auth", "prov", journal_event("tx-2")), Err("duplicate event id"));
    }

    #[test]
    fn authorization_and_provenance_are_required() {
        let mut journal = MonetaryJournal::default();
        assert_eq!(journal.append("e1", "2026-09-19T06:00:00Z", "tx-1", "", "prov", journal_event("tx-1")), Err("missing authorization"));
        assert_eq!(journal.append("e1", "2026-09-19T06:00:00Z", "tx-1", "auth", "", journal_event("tx-1")), Err("missing provenance"));
        assert_eq!(journal.entries().count(), 0);
    }

    #[test]
    fn mc_and_mc7_trace_as_distinct_currencies() {
        let mut journal = MonetaryJournal::default();
        let mc = MonetaryEvent::LedgerCommitted { transaction_id: "tx-mc".into(), currency_id: "MC".into(), idempotency_key: "i1".into() };
        let mc7 = MonetaryEvent::LedgerCommitted { transaction_id: "tx-mc7".into(), currency_id: "MC7".into(), idempotency_key: "i2".into() };
        assert!(journal.append("e1", "2026-09-19T06:00:00Z", "MC", "auth", "prov", mc).is_ok());
        assert!(journal.append("e2", "2026-09-19T06:01:00Z", "MC7", "auth", "prov", mc7).is_ok());
        assert_eq!(journal.trace_currency("MC").count(), 1);
        assert_eq!(journal.trace_currency("MC7").count(), 1);
    }
}
