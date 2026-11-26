# Multi-Sample Archive Availability v0.1 — DRAFT / GO-13 HOLD

`tools/multi_sample_archive_availability.py` extends the existing signed
single-chunk verifier without introducing custody or release authority.
The caller independently pins the manifest hash and archive head, generates
a fresh unpredictable 256-bit seed *after* manifest commitment, and issues
challenges for exactly the deterministic selected indices and nonces.

Selection uses SHA-256 domain separation, unbiased rejection sampling,
and selection without replacement (maximum 64 samples/1024 chunks).
Every challenge includes the committed manifest, unique derived nonce,
required selected index, requester, and an independently checked time
window. Every reply is checked with the established Ed25519 signature,
exact byte length, SHA-256 integrity and current custodian trust policy.
A single failure rejects the whole batch. Coverage is expressed as
integer parts per million and checked against a caller-specified floor.

The caller must preserve signed challenges, an independent seed and
manifest pin, a trusted clock, and consumed nonces durably. The verifier
does not issue challenges, access external content, persist nonce
consumption, attest geographic independence, or prove whole-archive
durability. Deterministic selection is not unpredictable unless the
caller provides a fresh unpredictable secret seed. The verification
result is only `pending-review`, with GO-13 HOLD and authorization DENY.

Run: `python3 -m unittest discover -s tests -p 'test_multi_sample_archive_availability.py' -v`.
