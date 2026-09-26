# EVA-LA-001 / A1 — contract candidate v0.1

Status: implementation candidate, **DRAFT**. This is the first bounded build unit from [BOUW L.A.](https://app.notion.com/p/3de29e9a126a80ba8f3ff0e7f2097e97), not completion of the Citadel v0.1 activation gate.

The [additional L.A. website](https://sfs-u8anx1wcwdug.live-website.com) presents Locus Amoenus as a Reference Citadel, Worlds including Eva, and the PALACO-INDUSTRIE/F.I.E. vision. It is recorded as presentation context; the concrete `EVA-LA-001` / `WORLD-EVA-001` identifiers and technical boundaries below come from BOUW L.A. Its visual material is not treated as cryptographic evidence.

## Deliverables and boundary

- Rust `CitadelManifest` and `CanonicalRecordEnvelope` contracts, strict parser, canonical encoder, profile-based digests, offline verifier CLI.
- A separately implemented Python standard-library verifier; it imports no Rust code and has no database/UI dependency.
- Frozen three-record vector: question → evidence → epistemic assessment. Expected canonical payload bytes and digests are committed separately.
- `VALID | INVALID | INCOMPLETE | CONFLICT | UNKNOWN`, explicitly scoped to **A1_ENVELOPE_INTEGRITY**. Every receipt leaves identity, authority, signatures, current validity and ArchiveRoot inclusion `UNKNOWN`.

No server, authentication, PostgreSQL ledger, actual authorization, signed proof, ArchiveRoot, replay-protected write API or lifecycle activation is delivered by A1. The record envelope reserves their references. Domain payload schemas, lifecycle evaluation and complete proof verification belong to subsequent units. Nothing here changes the existing Rust execution boundary or the RIO websites.

## Manifest v0.1

All fields in `manifest.schema.json` are mandatory; extra fields are rejected. The frozen manifest is `verification/citadel-a1/manifest.json`.

Identity: `EVA-LA-001`, `WORLD-EVA-001`. Purpose: Long-Term Constitutional Memory. Edition: Foundation / canonical baseline. Presentation: Foundation + Black Edition. Lifecycle is `DRAFT`. A1 rejects unsupported versions/profiles/lifecycles with `UNKNOWN`; it does not promote a manifest to ACTIVE.

The manifest binds `canonical_encoding: PALACO-JSON-A1` and `cryptographic_profile: SHA256-DOMAIN-A1`. Each record includes `manifest_digest` to bind these choices and its resource context. Profiles are versioned identifiers: extending algorithm support requires an explicit new implementation and interoperability vector. Unknown profiles never fall back silently.

## Canonical encoding: PALACO-JSON-A1

This is a deliberately restricted deterministic JSON profile, **not a claim of RFC 8785 conformance**.

1. UTF-8 without BOM; no duplicate object keys at any depth, including duplicate escaped spellings.
2. Object keys match `[a-z][a-z0-9_]{0,63}`. Sort keys in ascending ASCII byte order.
3. Values: null, booleans, Unicode scalar strings, arrays, objects and integers in `[-9007199254740991, 9007199254740991]`. Floating-point syntax, exponents, negative zero and non-finite values are forbidden.
4. Preserve string Unicode scalar values exactly; **no Unicode normalization**. Escape quote and backslash; use `\b`, `\t`, `\n`, `\f`, `\r`; other U+0000–U+001F controls use lowercase `\u00xx`. Other characters, including non-ASCII, remain UTF-8. Lone surrogates are invalid.
5. No insignificant whitespace or final newline in canonical bytes. Array order is significant. Nesting is at most 64 container levels; verifier input is at most 1 MiB.
6. Nullable envelope fields must be explicitly present as null; omission is not an alias for null. Unknown envelope/manifest fields are invalid. Payload must be an object; its semantic schema is not asserted by A1.

## Digests and exclusions

SHA-256 lowercase hex, 64 characters. Hash UTF-8 domain prefix including a final NUL byte, followed immediately by canonical bytes:

| Digest | Prefix | Value |
|---|---|---|
| manifest_digest | `PALACO:CITADEL:MANIFEST:A1\0` | Manifest minus only `manifest_digest` |
| payload_digest | `PALACO:CITADEL:PAYLOAD:A1\0` | Entire payload object |
| record_digest | `PALACO:CITADEL:RECORD:A1\0` | Entire envelope (including payload) minus only `record_digest` |

No field other than the explicitly excluded self-digest is dropped. The display timestamp is hashed as recorded, but never used to order records, infer freshness or authorize execution. A1 signatures must be null for a VALID integrity result; a supplied signature produces UNKNOWN after integrity checks because signature verification is not implemented.

## Chain and dependency rules

The bundle has exactly `manifest` and `records`. It contains the complete prefix from sequence 1 to the anchored head. The first previous digest is null; subsequent digests reference the immediately preceding record. Sequences are contiguous, safe positive integers. IDs are unique within the bundle. No sorting or repair occurs during verification.

`provenance_refs`, `evidence_refs`, `authorization_ref` and `trusted_time_evidence` resolve to prior record IDs within the same bundle. Self-references are invalid; missing/not-yet-prior dependencies are INCOMPLETE. Evidence refs point to EvidenceObject; authorization refs point to AuthorizationRecord. Merely resolving that reference does **not** validate authorization or constitutional authority. Per-list duplicate references are rejected.

Epistemic envelope labels: UNKNOWN, SUPPORTED, CONTESTED, INSUFFICIENT, REFUTED. These are recorded claims, not assertions established by the verifier. Record types and required fields are specified in `record-envelope.schema.json` and the Rust type. The type list is reserved for subsequent domain payload implementations; accepting an envelope does not mean those workflows are implemented.

## External anchors and result precedence

Both CLIs require an expected manifest digest and expected head digest supplied separately from the bundle. For this fixture, obtain them from the separately versioned `expected.json`. In production they must come from an independently trusted channel; accepting attacker-supplied anchors defeats truncation/substitution protection.

The verifier returns the first detected issue in input order: malformed JSON/profile → schema/profile support → manifest digest/anchor → record shape/context/identity/sequence → digests → dependencies → final anchored head → unsupported signatures. Missing tail/head or dependency yields INCOMPLETE; an empty record list yields UNKNOWN; conflicting IDs/context yield CONFLICT. This is diagnostic precedence, not a risk ranking. Every result other than VALID fails the CLI (nonzero exit), and VALID is still limited to integrity.

## Reproduce

```sh
cargo test -p palaco-citadel-contracts
cargo build -p palaco-citadel-contracts --bin citadel-a1
python3 tools/citadel_a1/test_verify.py
CITADEL_A1_BINARY="$PWD/target/debug/citadel-a1" python3 tools/citadel_a1/test_verify.py
```

Verify the frozen vector directly with **either** executable:

```sh
cargo run -p palaco-citadel-contracts --bin citadel-a1 -- verification/citadel-a1/bundle.json eead3c419c98cebf76c95b9a44fc0a198ce0c1dfcc9f92b98e59c2f1c66e66e7 d68236c4889b07210e8687149bf81b85458228fe1cb40debeca70d63e2aec512
python3 tools/citadel_a1/verify.py verification/citadel-a1/bundle.json eead3c419c98cebf76c95b9a44fc0a198ce0c1dfcc9f92b98e59c2f1c66e66e7 d68236c4889b07210e8687149bf81b85458228fe1cb40debeca70d63e2aec512
```

`generate_vector.py` is an explicit fixture-authoring tool. CI never regenerates expected bytes/hashes. Deliberate contract changes require review of both the new vector and both implementations.

## Threat model v0.1 (A1 scope)

Untrusted input includes the entire bundle, timestamps, actor references, signatures, epistemic labels and claimed permissions. Test adversaries modify/reorder/remove records, duplicate keys/IDs, substitute resource context or profiles, and supply oversized/deep/noncanonical values. Hashes detect changed bytes relative to trusted anchors; they do not prove truth, origin, consent, actor identity, current validity or durable append-only storage. An attacker controlling the anchor channel can replace the entire history. Database append-only enforcement, authenticated writes, scoped authorization, concurrency, idempotency, signatures, trusted time, archive inclusion and revocation effects remain future gates. Do not expose A1 as an authorization endpoint.
