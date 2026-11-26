# Sampling Handoff Receipt Ledger v0.1 — DRAFT · GO-13 HOLD

`tools/sampling_handoff_receipt_ledger.py` integrates the strict
`sampling_succession_evidence_handoff.verify_receipt` gate with a
transactional SQLite receipt ledger. Under `BEGIN IMMEDIATE`, the
complete existing SHA-256 hash chain and separate nonce index are
revalidated before the complete signed handoff history is independently
reverified. One transaction writes the receipt fingerprint and the
nonce index together. Rejected signatures and replayed nonces cannot
become successful receipt records.

Each event binds the recipient ID, verified recipient signing key,
package SHA-256, signed receipt evidence SHA-256, consumed nonce,
monotonic sequence and prior event hash under a domain-separated hash.
Receipts from the same key about the same package cannot be issued
twice even with a different nonce. Read-only `inspect` verifies the
hashes, the nonce index, continuous sequence and separately pinned
head hash and minimum receipt count.

**Threat boundary:** SQLite is local mutable storage, not an
independent immutable archive. The caller MUST provide up-to-date,
separately authenticated head/count pins before every append and
review, and must retain those anchors durably. For cross-device
replay protection a separately administered shared nonce authority
is still necessary. The module records receipt digests, NOT source
files and not proof of off-device storage, legal independence or
physical delivery. No signer private keys are used and no remote
requests are issued.

All positive outcomes remain `pending-review`, with
`release_gate=HOLD`, authorization DENY and no merge, deployment
or automatic restoration.

Test: `python3 -m unittest discover -s tests -p 'test_sampling_handoff_receipt_ledger.py' -v`.

## Post-write integrity hardening (2026-11-23)

After writing both tables inside the same `BEGIN IMMEDIATE` transaction,
the ledger rescans the entire receipt chain and nonce index **before commit**.
If the expected sequence, new head, nonce binding, or chain integrity is
missing, the transaction is explicitly rolled back and the receipt is denied.
Negative regression tests install SQLite triggers that delete inserted nonces
or corrupt event hashes and verify no receipt rows survive. This detects
some forms of in-transaction tampering; it does not make local SQLite
storage tamper-proof or replace independently authenticated external pins.

## Bounded nonce-index integrity scan (2026-11-24)

Both the receipt history and its nonce index are read with a strict
`MAX_RECORDS + 1` query limit. An index exceeding `MAX_RECORDS`
fails closed before the index set is materialized. The full expected
nonce/sequence mapping must still exactly match the bounded receipt
chain. Regression tests cover an extraneous nonce and an oversized
index on both read-only inspection and subsequent registration.

This provides a bounded database read; it is **not** a storage-size quota,
external nonce authority, or protection from every SQLite resource
exhaustion vector. GO-13 remains HOLD and all authorization is denied.

## Individuele read-only ontvangstinspectie (2026-11-24)

`inspect_entry(db, expected_head, minimum_receipts, sequence)`
opens SQLite in read-only mode and verifies the **entire** local receipt
chain plus nonce index within one database read transaction before exposing
the requested record metadata. Both an independently authenticated exact
head hash and minimum entry count are mandatory. Nonexistent or invalid
sequence numbers, chain manipulation and rollback fail closed.

The response provides the recipient, signing-key identifier, package hash,
receipt nonce, receipt digest, previous event hash and event hash for
independent forensic comparison. It does **not** expose source documents,
validate off-device delivery, grant storage custody or authorize anything.
All successful lookups remain `pending-review`, `HOLD`, and DENY.

## Signed evidence re-verification (2026-11-24)

`verify_entry_evidence(db, package, receipt, trust, expected_head,
minimum_receipts, sequence)` first verifies the entire read-only local
chain, nonce index and separately trusted head/count pin, then performs
fresh Ed25519 receipt signature, package history, witness eligibility and
recipient revocation checks through the strict handoff verifier. Only if
the signed receipt's digest, recipient, key, package digest and nonce
match the indexed row does it return a positive **pending-review** result.

The externally managed `used_nonces` policy must be supplied as an
evidence-verification snapshot that does not incorrectly treat the
receipt currently under examination as a *new* replay attempt; the
ledger itself already requires that nonce to be present. The caller
must independently authenticate the trust roots and pins. Validation
is read-only and is not a certificate of delivery, possession or legal
independence. All authorization remains DENY and release GO-13 HOLD.

## Atomic rollback on nonce insert failure (2026-11-24)

The two-table receipt registration transaction now explicitly calls
`rollback()` when the second insert raises `sqlite3.IntegrityError`.
Without that step, returning normally from a Python SQLite connection
context manager could commit the first receipt row even though writing
the nonce index failed. A negative regression test injects an aborting
nonce-table trigger, rejects the attempted handoff and confirms **both**
tables remain empty with the genesis head unchanged.

This protects the local atomicity contract for that failure path; it
does not provide external immutability, a distributed transaction
protocol, or delivery/custody proof. GO-13 remains HOLD, authorization DENY.

## SQLite schema-drift guard (2026-11-24)

Before scanning the receipt hash chain or nonce index, the ledger
compares the two expected SQLite table definitions against the
definitions retained in `sqlite_master`. It denies unexpected
columns, missing constraints or altered table definitions. Checks run
on both registration and read-only inspection. Regression tests cover
a preexisting receipt table missing its unique key/package constraint,
and an added column after a valid anchored receipt is recorded.

This local schema check is an integrity gate, not a defense against
an attacker who controls the database and execution environment.
Independent authenticated head/count pins remain required; all
outcomes preserve GO-13 HOLD and authorization DENY.

## Recheck after evidence verification (2026-11-24)

The read-only `verify_entry_evidence` path now repeats the pinned full-ledger
and nonce-index inspection **after** cryptographic receipt verification.
The verified entry must be identical to its initial snapshot. A mutated
event hash, removed nonce, missing record, or changed trusted head between
the two inspections results in `handoff-entry-changed-during-verification`,
with all authorization denied. Two negative tests inject exactly these
mutations while receipt verification is executing.

This narrows a time-of-check/time-of-use window but does **not** provide
a continuous lock across databases or remote sources: another change may
occur after the final inspection. The caller must retain authenticated
external pins and enforce custody decisions independently. GO-13 HOLD.

## SQLite structural and reference integrity (2026-11-24)

The common ledger scan now requires SQLite `PRAGMA quick_check(1)`
to report `ok` and `PRAGMA foreign_key_check` to return no violations,
after the schema contract has been validated and before checking the
SHA-256 event chain. Both read-only inspection and transaction-bound
registration fail closed on storage corruption or orphaned nonce links.
Regression tests cover clean storage, a deliberately orphaned nonce
reference, and a simulated failing storage integrity check.

A `quick_check(1)` is limited diagnostic coverage, **not** a complete
filesystem, hardware, or independent archive integrity guarantee.
The existing chain, external pins, nonces, signed evidence and release
controls remain mandatory. Authorization DENY, GO-13 HOLD.

## Active SQLite foreign-key enforcement (2026-11-24)

Registration now explicitly enables `PRAGMA foreign_keys=ON` on each
new writer connection **before** `BEGIN IMMEDIATE`, then checks that
SQLite reports enforcement as enabled. A missing capability is denied
before any table write. The existing read-only foreign-key check remains
in place to detect damage already present on disk.

A negative regression test installs a trigger that attempts to add a
nonce pointing to a nonexistent receipt during an otherwise valid
registration. The foreign-key violation must abort the transaction;
both tables must remain empty and the genesis head unchanged. This
enforces local referential integrity at write time but does not make
SQLite immutable or replace authenticated external ledger anchors.
GO-13 HOLD and authorization DENY remain mandatory.

## Full SQLite index and constraint validation (2026-11-24)

Storage validation now uses `PRAGMA integrity_check(1)`, replacing
`quick_check(1)` in the shared ledger scan. Unlike the faster check,
the full integrity check also examines UNIQUE constraints and index/table
consistency. The argument `1` limits diagnostic output to the first
error; it does not limit the internal integrity work performed.
`PRAGMA foreign_key_check`, schema validation, nonce-index comparison,
the SHA-256 chain and independently authenticated head/count pins remain
mandatory.

New regressions assert use of `integrity_check(1)` and fail-closed
behavior for a deliberately CHECK-violating row. The stronger SQLite
check may increase inspection and registration latency; it cannot
establish external immutability, physical delivery or custody. Every
positive outcome remains pending-review and GO-13 HOLD.

## Read-only review manifest export (2026-11-24)

`export_review_manifest(db, expected_head, minimum_receipts)` opens a
read-only SQLite transaction, rechecks the complete ledger chain, schema,
indexes and nonce bindings, and enforces the independent head/count pin.
It returns a bounded ordered list of receipt metadata, the head hash,
record count, and a domain-separated SHA-256 commitment over canonical
JSON. The export is for independent comparison and may be stored
externally by a reviewer, but **is not signed or externally anchored by
this module**. It does not include original delivery content or private
signing material.

A missing store, untrusted head, historical rollback or altered record
fails closed. Manifest integrity proves only agreement with the supplied
authenticated anchor at the time of the SQLite read transaction.
Revalidation against independently retained anchors remains necessary;
export does not confer custody, possession or authority. GO-13 HOLD.

## Independent offline review-manifest verification (2026-11-24)

`verify_review_manifest(manifest, expected_manifest_sha256,
expected_head, minimum_receipts)` is database-independent and
network-free. It requires separately authenticated expected manifest
SHA-256, exact ledger head and minimum receipt count. Strict schema
checks reject extra fields, incorrect value types and oversized
records. It recomputes each domain-separated event hash, validates
contiguous sequence and prior-hash linkage, rejects nonce reuse and
duplicate recipient-key/package bindings, and checks the canonical
manifest commitment. Five regressions cover valid offline verification,
entry manipulation, pin mismatch/rollback, replay and schema drift.

A successful result is **pending-review**, not signature verification
of the original receipt or independent custody attestation. The
caller must authenticate the three pins through a separate trust
process. This verifier does not connect to SQLite, sign anything,
grant access or change GO-13 HOLD / authorization DENY.

## Offline append-only manifest succession (2026-11-24)

`verify_manifest_succession(previous_manifest, previous_sha256,
previous_head, current_manifest, current_sha256, current_head,
minimum_previous_receipts)` verifies each manifest independently,
using separately authenticated full-manifest SHA-256 and exact ledger
head pins. It then requires the complete prior entry list to be the
exact prefix of the current list. Equal snapshots are allowed but
explicitly reported as having no new receipts; a genuine extension
must link its first appended record to the previous head.

This detects rewritten prior entries, truncated histories, incorrect
independent pins and invalid new hash-chain links. Regression tests
exercise equal snapshots, genuine append-only growth, rewritten history,
pin mismatches and rollback. Constructed fixtures represent *ledger
consistency*, not newly issued signed receipts.

The verifier performs no database access, writes, signing or network
operations. External pin authenticity and receipt-signature validation
remain separate responsibilities. Every positive result is
`pending-review`; GO-13 HOLD and authorization DENY remain in effect.

## Offline append-only delta proof (2026-11-24)

`create_review_delta` verifies two fully pinned manifests, then produces
a compact `0.1.0` delta containing only appended receipt entries,
prior/current receipt counts and prior/current ledger heads, protected
by a domain-separated SHA-256 digest. `verify_review_delta` accepts the
independently authenticated *previous manifest*, its digest/head, the
delta and independently authenticated delta digest/current head. It
reconstructs the current history offline and reuses the strict manifest
and succession verifiers. Count mismatches, unknown fields, modified
delta data, invalid hash links and replayed nonce/key-package pairs
are denied. A zero-length append is allowed but grants no authority.

This reduces transport size but does not authenticate the original
receipt signatures or establish actual delivery, possession or legal
custody. Neither the delta digest nor the head pins are signed by this
module. Reviewers must authenticate and durably retain pins through
a separate trust channel; all positive results remain pending-review,
GO-13 HOLD and authorization DENY.

## Strict independently pinned delta review (2026-11-24)

`verify_review_delta_with_manifest_pin` adds a mandatory, independently
authenticated **current full-manifest SHA-256** to the existing offline
delta verification. First it revalidates the prior manifest, delta digest,
head pins, reconstructed complete chain, sequence and replay uniqueness.
It then requires the computed current-manifest digest to equal the
separately authenticated expected manifest digest. Missing, malformed
or mismatched current-manifest pins fail closed. Three negative/positive
test cases cover correct pins, missing/incorrect pins and propagation
of broken-chain failures.

An independent digest is meaningful only if the caller has obtained and
authenticated it through a distinct trust channel; deriving the expected
pin from the received delta would defeat the additional trust boundary.
The older verifier is retained for backward compatibility and remains
review-only. Neither verifier establishes handoff delivery, custody,
signature validity of original receipts or authorization.
GO-13 HOLD, authorization DENY.

## Offline competing-delta fork assessment (2026-11-24)

`assess_review_delta_fork` verifies two proposed delta branches
individually against their own independently authenticated delta
SHA-256, current manifest SHA-256 and current ledger heads, sharing one
separately authenticated previous manifest and its pins. Only after
both branches validate does the assessment compare their appended
entry sequences. Divergent entries at the same sequence indicate
a split-view/fork incident and return `fork_detected=True`, state
`quarantined`, and no authorization. Identical branches or one
branch that is an exact prefix of the other are reported as
nonconflicting **pending-review** outcomes; neither is promoted
to canonical status.

Four regressions cover independently valid divergent histories,
identical histories, a mismatched right-hand manifest pin, and valid
prefix extension. External anchors remain caller-supplied and must
be authenticated independently. A fork assessment does not establish
physical custody, independent archiving, or permission to reconcile
a conflict automatically. GO-13 HOLD / authorization DENY.

## Deterministic fork conflict evidence (2026-11-24)

For two individually valid, independently pinned delta histories that
diverge at the same receipt position, the fork assessor now returns a
strictly informational `fork_evidence` object. It records the earliest
conflicting sequence, both event hashes, previous head and manifest
commitment, both delta SHA-256 commitments, both current manifest
commitments, and both branch heads. The canonical JSON object is hashed
with the domain-separated prefix
`PALACO-SAMPLING-HANDOFF-FORK-EVIDENCE-V1\x00`.
Reviewers can independently recompute this evidence commitment.
Regression assertions cover the divergence index, independent pins,
commitment recomputation, and absence of evidence on identical branches.

The evidence is **not** a signed independent witness statement and is
not an instruction to merge, select a branch or release quarantine.
Conflict outcomes remain `state=quarantined` and
`authorization_granted=False`. External authentication and durable
custody remain separate obligations; GO-13 HOLD stays enforced.

## Independent offline fork-evidence reverification (2026-11-24)

`verify_review_fork_evidence` takes the independently authenticated
prior-manifest and two competing delta pin sets, along with the recorded
fork-evidence object and a separately authenticated fork-evidence
SHA-256 commitment. It fully re-verifies both delta branches, recomputes
the earliest divergence, compares the entire evidence record against
the freshly derived result, and checks the domain-separated commitment.
No SQLite database or network access is required.

Four regressions exercise successful independent offline reverification,
tampered evidence, missing or incorrect evidence pins, corrupted branch
anchors, and the case where branches no longer conflict. Invalid inputs
return explicit failure without selecting a canonical branch.

Even a successfully reverified conflict stays `quarantined`,
`authorization_granted=False`, and `release_gate=HOLD`. This is an
integrity check against authenticated external pins, **not** an external
witness signature or independent custody certificate. GO-13 HOLD remains.

## Fail-closed delta scalar validation (2026-11-25)

The offline delta verifier now validates each appended receipt entry
**before** constructing or hashing any canonical delta JSON. Every
sequence must be an exact integer equal to its expected contiguous
position, recipient identifiers must match the existing bounded
identifier grammar, and every digest/key/nonce field must be a
properly formatted SHA-256-size hexadecimal string. Nested values,
booleans in sequence slots, oversized strings and non-contiguous
sequences are rejected with `invalid-review-delta-entry`.

The change reduces wasted serialization and untrusted-input exposure
for malformed delta records while preserving domain-separated hashes
and all independent pin checks. Two regression methods include multiple
hostile scalar and sequence cases and assert that invalid inputs are
rejected **before** the delta hash function can run. This is not a
streaming byte limit on serialized untrusted network payloads; upstream
transport/parsing limits remain necessary. GO-13 HOLD, authorization DENY.

## Bounded untrusted delta JSON decoding (2026-11-25)

The new `verify_review_delta_json` entry point accepts *bytes only*,
requires a nonempty payload at most 8 MiB, decodes strict UTF-8, rejects
duplicate object keys at every nesting level, and rejects non-finite
JSON constants, invalid syntax and excessive nesting before invoking
the existing pinned offline delta verifier. JSON parsing occurs only
after the byte-size/type gate. The original programmatic dictionary
verifier remains supported, but callers accepting externally transmitted
JSON bytes should use this bounded decoding entry point.

Four new regression methods cover valid byte payloads, byte-size/type
limits without entering the parser, duplicate keys at the root and
inside receipt entries, malformed UTF-8 and non-finite constants.
This check bounds the **received serialized document**, not overall
process memory, the size of trusted previous manifests, or transport
buffering upstream. Separate size limits are still needed at the HTTP,
file and message acquisition layers. No pin issuance, permission,
delivery or custody is implied. GO-13 HOLD / authorization DENY.

## Strict numeric JSON-token boundary (2026-11-26)

The byte-bounded `verify_review_delta_json` entry point now installs
explicit JSON numeric parsing callbacks. Integer tokens longer than ten
decimal characters are rejected **before** conversion into Python
integers. Floating-point and exponent-form numeric tokens are always
rejected because the review-delta schema defines only integer sequence
and count fields. Existing strict UTF-8, duplicate-key, non-finite
constant, 8 MiB size, shape and independent-pin checks remain in force.

Three regression methods cover decimal/exponent notation, oversized
integer tokens, and bounded-but-out-of-schema integer values. The
ten-character integer-token cap prevents disproportionately expensive
integer parsing; the existing structural validator continues to enforce
the much tighter permitted count and sequence ranges. JSON acquisition
layers must still impose their own byte limits. No authorization,
custody, merge or release authority follows; GO-13 HOLD remains.

## Strict JSON delta verification with separate manifest anchor (2026-11-26)

The new `verify_review_delta_json_with_manifest_pin` entry point
applies the exact same bytes-only, 8 MiB size, UTF-8, duplicate-key and
numeric-token restrictions as the basic JSON intake route. After bounded
decoding it calls the strict offline delta verifier and **requires** an
independently authenticated expected full current-manifest SHA-256.
A missing or mismatched manifest anchor fails closed. The strict route
must not derive its expected manifest pin from the received delta.

Both JSON entry points now reuse one shared decoder to prevent security
policy divergence. Four new regression tests cover a valid pinned
offline payload, absent/incorrect manifest pins, duplicate keys or an
oversized request before hashing, and an invalid delta hash. No signing,
custody attestation, automatic branch selection, authorization or
deployment is performed; GO-13 remains HOLD / DENY.
