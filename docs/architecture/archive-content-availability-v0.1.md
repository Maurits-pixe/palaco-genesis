# Archive Content Availability v0.1 — DRAFT · GO-13 HOLD

`tools/archive_content_availability.py` checks one independently selected
archive chunk per fresh challenge. A canonical manifest commits to a
separately pinned archive-record head, exact total byte length, fixed
chunk length, and SHA-256 hashes of *all* chunks. The manifest digest is
domain-separated and MUST be independently authenticated. The
requester supplies an independently generated 256-bit nonce, index
chosen after the manifest was pinned, requester ID, and a time window.

The custodian response includes the actual chunk bytes as Base64 and an
Ed25519 signature over the request, key ID, and chunk bytes, with
domain separation. Verification checks the exact expected final-chunk
length, SHA-256 equality, signature, independent trust roots, current
revocations, nonce replay policy, requester and trusted current time.
Malformed fields and unexpected privilege/authorization fields fail closed.

**Limitations:** The module does not generate challenges, sign anything,
retrieve archive content, maintain consumed-nonce history, or provide
trusted time. A caller must maintain those controls independently.
A sampled valid byte sequence gives *limited evidence* of possession of
that chunk at verification time. It is NOT a proof of geographic
remoteness, durable independent storage, full archive recoverability
or future content availability; chunks may be proxied or precomputed.
No Merkle multiproof or erasure-coding proof is claimed. Valid output is
always `pending-review` and GO-13 remains HOLD, with release,
merge, recovery and deployment unauthorized.

Run `python3 -m unittest discover -s tests -p 'test_archive_content_availability.py' -v`.
