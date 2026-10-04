# BOTERHAM Integration Contract v0.1.0

BOTERHAM is an administrative orchestration boundary over canonical monetary contracts.

## Canonical chain
IDENTITY → CURRENCY → POLICY → PROVENANCE → AUTHORIZATION → LEDGER → TRACEABILITY

## Required domain contracts
CurrencyId, CurrencyVersion, WalletId, TransactionId, LedgerEntryId, HotspotId, MonetaryAuthorizationId, MonetaryPolicyId, ComplianceStatus and CurrencyScope.

## M.C. / M.C.7
They are separate instruments with independent policy identifiers and lifecycle state.

## Security
Administrative access cannot mint authority. Provenance cannot substitute for authority. Balance mutation requires a committed transaction. Reversal preserves lineage. Revocation propagates. Expiration remains distinct.

This contract is intended for sandbox/pilot implementation before any production monetary execution.
