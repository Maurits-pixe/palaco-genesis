# BOTERHAM Audit & Rewards Boundary — Sandbox v0.1

The monetary sandbox now has an explicit event vocabulary and reward boundary.

## Event contract

Supported event types:

- `currency.registered`
- `currency.activated`
- `wallet.created`
- `wallet.profile_changed`
- `account.created`
- `reward.granted`
- `ledger.committed`
- `transaction.reversed`

Events are descriptive audit records. An event does not itself grant authority.

## Reward contract

A `RewardGrant` requires:

- a reward ID;
- target account;
- active currency;
- reward rule reference;
- authorization;
- provenance;
- positive amount.

The sandbox explicitly rejects transferable reward currencies. A reward becomes a ledger intent/event; it does not directly mutate a balance.

## Constitutional separation

`REWARD RULE → EVIDENCE/PROVENANCE → AUTHORIZATION → LEDGER POSTING → AUDIT EVENT`

Therefore:

**REWARD ≠ AUTHORITY**  
**EVENT ≠ AUTHORIZATION**  
**BALANCE ≠ DIRECT MUTATION**

Production reward issuance remains gated by legal, security, operational and constitutional approval.
