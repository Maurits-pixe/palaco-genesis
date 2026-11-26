# External Archive Custody Claim v0.1 — DRAFT / GO-13 HOLD

`tools/external_archive_custody_claim.py` verifies a custodian's Ed25519
response to a caller-authenticated, freshly issued 256-bit nonce. The
challenge binds requester, issue/expiry epochs, precise latest archive
head digest and archive record count, and underlying audit head digest.
The caller must separately authenticate expected nonce, requester, and
current epoch. The response is a strictly scoped signed **availability
claim** using domain `PALACO-EXTERNAL-ARCHIVE-CUSTODY-CLAIM-V1`.

Before accepting any claim, the checker revalidates all signed archive
records, witness statements, receipt-audit hashes, independently pinned
genesis/head hashes, minimum counts, custodian roots and revocations.
Unknown, expired, previously used or altered nonces, wrong archive
versions and incorrect signatures fail closed. The caller MUST track
consumed nonces in an independently managed durable register; the
module does not record or consume them, issue challenges or provide
trusted time.

**Security limit:** A valid signature proves that a private key signed
the claim; it does NOT prove the custodian truly possesses or can
retrieve the archived bytes, was geographically remote, is an
independent legal entity, or can demonstrate durable storage. A
future real custody proof needs an independently administered
challenge service and a content-availability sampling protocol.
All successful claims remain `pending-review` with GO-13 HOLD;
no issuance, release, restore, merge or deployment is performed.

Run `python3 -m unittest discover -s tests -p 'test_external_archive_custody_claim.py' -v`.
