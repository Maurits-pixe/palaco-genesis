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
        registry.register(CurrencyDefinition::sandbox_master_coin()).expect("test setup");
        registry.activate("MC", "auth", "prov").expect("test setup");
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
        registry.register(CurrencyDefinition::sandbox_master_coin()).expect("test setup");
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
        wallets.create_wallet(Wallet { wallet_id: "w1".into(), owner_id: "c1".into(), profile: WalletProfile::Blanco, account_ids: Vec::new() }).expect("test setup");
        wallets.change_profile("w1", WalletProfile::Filantroop).expect("test setup");
        let history: Vec<_> = wallets.profile_history("w1").collect();
        assert_eq!(history, vec![WalletProfile::Blanco, WalletProfile::Filantroop]);
    }

    #[test]
    fn mc_and_mc7_remain_separate_accounts() {
        let mut currencies = CurrencyRegistry::default();
        currencies.register(CurrencyDefinition::sandbox_master_coin()).expect("test setup");
        currencies.register(CurrencyDefinition::sandbox_mission_coin7()).expect("test setup");
        currencies.activate("MC", "auth-mc", "prov-mc").expect("test setup");
        currencies.activate("MC7", "auth-mc7", "prov-mc7").expect("test setup");

        let mut wallets = WalletRegistry::default();
        wallets.create_wallet(Wallet { wallet_id: "w1".into(), owner_id: "c1".into(), profile: WalletProfile::Blanco, account_ids: Vec::new() }).expect("test setup");
        wallets.add_account(WalletAccount { account_id: "a-mc".into(), wallet_id: "w1".into(), owner_id: "c1".into(), currency_id: "MC".into() }, &currencies).expect("test setup");
        wallets.add_account(WalletAccount { account_id: "a-mc7".into(), wallet_id: "w1".into(), owner_id: "c1".into(), currency_id: "MC7".into() }, &currencies).expect("test setup");
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
