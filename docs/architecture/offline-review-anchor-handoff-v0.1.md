# Offline Review Anchor Handoff v0.1 — DRAFT / HOLD

This local module packages a previously signed Ed25519 review-history witness
into a canonical, bounded JSON handoff envelope, addressed to a declared
recipient. The bundle includes a detached signed anchor, a SHA-256 hash of its
canonical envelope, and a domain-separated SHA-256 package digest.

`prepare(...)` first verifies the signed witness against the local history,
caller-supplied witness roots, revocations and minimum history entries; it
returns only in-memory JSON. It never publishes, signs, sends or saves data.

`verify_package(...)` requires an independently obtained package SHA-256,
the expected recipient, authenticated witness roots/revocations and a
freshness floor. It checks both digests, the Ed25519 signature and the local
history chain. An exact match is `pending-review` only.

**Trust limitations:** a recipient identifier in JSON does not authenticate
the actual custodian. A package digest that accompanies the package is not
independent evidence; the expected hash must arrive through another trusted
channel. A package may be replayed if the external minimum is stale. The
module has no immutable remote storage, transmission, receipts, trusted
timestamps, key custody, recovery authority or release capability. Keep
GO-13 HOLD, authorization DENY.

Test: `python3 -m unittest discover -s tests -p 'test_offline_review_anchor_handoff.py' -v`.
