# PALACO Genesis — Monetary Domain Contracts

This document reserves canonical cross-crate contracts for PALACO monetary infrastructure.

## Core types

- CurrencyId
- WalletId
- TransactionId
- HotspotId
- MonetaryAuthorizationId
- MonetaryPolicyId
- LedgerEntryId
- ExchangeOrderId
- ComplianceStatus
- CurrencyScope

## Event vocabulary

- CurrencyDefined
- CurrencyClassified
- CurrencyAuthorized
- CurrencyActivated
- CurrencySuspended
- CurrencyRevoked
- WalletCreated
- WalletPolicyChanged
- BalanceCredited
- BalanceDebited
- TransactionAuthorized
- TransactionCommitted
- TransactionReversed
- HotspotAuthorized
- HotspotRevoked
- ExchangeOrderCreated
- ExchangeOrderCancelled
- ComplianceStateChanged

## Invariants

1. What is signed shall be exactly what is verified.
2. Provenance never substitutes for authority.
3. Authority never substitutes for provenance.
4. Balance mutation requires a committed transaction.
5. Reversal preserves the original transaction lineage.
6. Revocation propagates to dependent execution paths.
7. Expiration is distinct from revocation.
8. Monetary state transitions are traceable.

## BOTERHAM boundary

BOTERHAM is the administrative orchestration layer. It may request operations but cannot bypass constitutional authorization.

## M.C. and M.C.7

Both instruments must have independent policy identifiers and lifecycle state. They must never be conflated merely because both are PALACO-native.

## Future WORLD currencies

World-specific currencies use the same contracts with a distinct issuer/scope and policy. The common registry prevents identifier collisions across PALACO's interstellar domain.
