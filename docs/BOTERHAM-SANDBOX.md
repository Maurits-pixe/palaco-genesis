# BOTERHAM Sandbox v0.1.0

The first executable monetary layer is deliberately a **sandbox contract**, not production money.

## Seed instruments
- M∆5TER COIN (M.C.)
- MISSION COIN 7 (M.C.7)

Both are non-production test assets until classification and authorization permit a later environment.

## Execution gate
A monetary operation may reach COMMITTED only when:
- authorization is present;
- provenance is present;
- lifecycle state is AUTHORIZED;
- currency and version are explicit.

The contract crate has no mint endpoint, no custody implementation and no external exchange implementation.

## Test progression
SANDBOX:
identity → currency definition → reward → ledger proposal → authorization → commit → audit

PILOT:
selected Citadel IDs and HOTSPOT participants, after separate approval.

PRODUCTION:
blocked until legal, security and operational gates are explicitly satisfied.
