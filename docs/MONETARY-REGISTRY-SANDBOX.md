# PALACO Monetary Registry — Sandbox Contract v0.1

## Scope

This document defines the first executable registry boundary for the PALACO monetary sandbox in `palaco-monetary-contracts`.

It is **not** a production payment, custody, banking, exchange, or public-issuance system.

## Currency Registry

The sandbox registers currencies by unique `currency_id`.

Canonical native instruments:

- `MC` — M∆5TER COIN
- `MC7` — MISSION COIN 7

They remain independent policy domains with independent definitions and bookkeeping.

A currency may be resolved for monetary use only while its compliance status is `Active`.

Activation requires both:

- authorization provenance/reference;
- lineage/provenance reference.

Suspended, revoked, and archived currencies fail closed.

## Wallet and Account Registry

A wallet binds:

- wallet ID;
- owner/Citadel ID;
- one owner-selected `WalletProfile`.

Accounts are explicitly currency-scoped. An account can only be created when:

1. its wallet exists;
2. the account owner matches the wallet owner;
3. the currency is active;
4. the account ID is unique.

Wallet profile changes append to a trace history; historical state is not silently overwritten.

## Sandbox Seeding

`sandbox_seed` does not mutate a balance.

It creates a balanced double-entry ledger transaction:

`TREASURY → LEDGER → WALLET ACCOUNT`

The transaction requires:

- active currency;
- positive amount;
- authorization;
- provenance;
- unique idempotency key.

Duplicate seeds are rejected.

## Constitutional boundary

`IDENTITY → CURRENCY → WALLET → ACCOUNT → LEDGER → PROVENANCE → AUTHORIZATION → BALANCE → COMMIT → TRACEABILITY`

This layer remains fail-closed and sandbox-only until separate legal, security, operational, and production authorization gates are satisfied.
