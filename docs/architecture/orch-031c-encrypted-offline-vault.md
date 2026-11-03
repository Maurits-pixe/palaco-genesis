# ORCH-031C — Encrypted Offline Vault

**Status:** DESIGN DRAFT — NOT AN IMPLEMENTED CRYPTOGRAPHIC STORE  
**Authority:** none; no identity, execution or release authority is created.  
**Dependency:** ORCH-031B fixture draft store (PR #197) is not suitable for secrets or personal data.

## Objective

Enable PALACO to preserve private drafts, evidence pointers, plans and locally staged work across long network outages. A user must be able to unlock locally when a previously provisioned device and appropriate local recovery material are available. No network availability may be assumed for routine local read/write after valid local unlock.

## Threat boundary

Protect against:
- theft of a powered-off device or copied vault files;
- malicious modification of encrypted vault records;
- wrong-user or wrong-device vault access;
- replay of older snapshots;
- crashes during writes or rotation;
- loss of internet and loss of remote key-service availability.

Explicit non-guarantees until separately engineered:
- compromise of a running, unlocked device;
- malicious local OS, debugger, root/administrator access;
- physical side-channel attacks;
- seamless recovery without a separately protected recovery capability;
- offline knowledge of newly issued remote revocations.

## Cryptographic contract

1. Use a vetted, maintained authenticated-encryption implementation; never invent encryption or nonce generation.
2. Generate a random per-vault data-encryption key. Never derive encryption directly from a public actor ID, P.P. number or project identifier.
3. Wrap the data key using a locally available, user/device-bound key-encryption mechanism. The approved platform-specific provider and portable fallback require separate review.
4. Password-based portable recovery, if enabled, requires a memory-hard KDF with recorded parameters, unique salt and independent recovery-secret policy.
5. Every encrypted record binds authenticated associated data to vault version, actor namespace, record ID, schema, policy epoch and key version.
6. Nonces must never repeat under a key. Generation, crash recovery and rotation must be proven by tests and the selected library's contract.
7. Authenticate before parsing or displaying plaintext. No partial plaintext on authentication failure.
8. Key material must not appear in logs, URLs, metadata, telemetry, crash reports or backups.
9. Rotation must be resumable and versioned; old key material cannot be discarded before proof of successful re-encryption and recovery.
10. Backups require independent authenticated encryption and a recoverable, user-controlled key strategy.

No cipher-suite, KDF parameter or key provider is approved by this design draft alone.

## Candidate technology assessment (not approval)

The following primary-source candidates are recorded for bounded prototype evaluation:

| Layer | Candidate | Evidence / review condition |
| --- | --- | --- |
| Authenticated record encryption | RustCrypto `chacha20poly1305` with `XChaCha20Poly1305` | Official crate documents 24-byte extended nonce. Verify exact crate release, nonce uniqueness, key lifecycle and platform support. |
| Portable passphrase recovery | RustCrypto `argon2` / Argon2id | Review password entropy, salt, memory/latency parameters and offline brute-force resistance. A password hash alone is not an encrypted vault. |
| Windows local key wrapping | Microsoft DPAPI user scope | Windows documentation describes user-credential-bound protection. Test offline access, account recovery, roaming profiles and device loss explicitly. |
| Other platforms | Platform keystore adapter undecided | No provider selected; fail closed until verified. |

Primary references:
- https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
- https://github.com/RustCrypto/password-hashes/blob/master/argon2/README.md
- https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata

Selection gates: source authenticity, maintenance, dependency/license audit, algorithm implementation review, RNG health, secret-memory handling, target-platform behavior and independent threat-model approval. No algorithm, DPAPI scope or KDF settings are committed for production by this document.

## Offline autonomy

| Operation | Desired offline behavior |
| --- | --- |
| Unlock previously provisioned local vault | Available without network after trusted local verification |
| Read/edit private local draft | Available in an unlocked vault |
| Search private local index | Available offline; index itself encrypted or otherwise protected |
| Stage intent | Available as non-authoritative encrypted local proposal |
| Issue/renew identity or execution authority | HOLD |
| Execute protected world/system mutation | HOLD without separately approved bounded capability |
| Reconcile staged work | Only after trusted connection, authentication, revalidation and explicit authority |

## Durable storage design

- Separate encrypted vault namespace per actor and device.
- Immutable record generations; no silent overwrite of the previous known-good generation.
- Crash-safe prepare/publish protocol with authenticated manifest and generation counter.
- Read-only recovery scanner that classifies incomplete generations without automatic deletion.
- Monotonic highest-known trusted time, policy epoch and revocation epoch recorded outside attacker-replayable trust where possible.
- Explicit space limits and disk-full recovery; full filesystem must not corrupt prior generation.
- Local journal receipts bind inputs and expected output digest. Successful local write is not a remote commit.

## Acceptance matrix

| ID | Negative/edge case | Required outcome |
| --- | --- | --- |
| ORCH031C-N01 | Wrong passphrase/device unlock | DENY, no plaintext |
| ORCH031C-N02 | Tampered ciphertext or associated data | DENY, no plaintext |
| ORCH031C-N03 | Reused nonce/key combination | Test rejects generator design |
| ORCH031C-N04 | Crash before publication | Previous good generation readable |
| ORCH031C-N05 | Crash after publication, before cleanup | One authoritative generation; recovery inspection |
| ORCH031C-N06 | Disk full during encryption/write | No partial published record |
| ORCH031C-N07 | Actor or device mismatch | DENY |
| ORCH031C-N08 | Snapshot rollback | Detect or HOLD for protected decisions |
| ORCH031C-N09 | Offline without network | Local unlock/read/write works after provisioning |
| ORCH031C-N10 | Missing local key provider | HOLD private vault access |
| ORCH031C-N11 | Key rotation interrupted | Recover last valid key generation |
| ORCH031C-N12 | Restored encrypted backup | Verify authenticity and prevent grant revival |
| ORCH031C-N13 | Background app/session switch | Keys cleared according to approved session policy |
| ORCH031C-N14 | Cross-actor search/cache | No private index leakage |
| ORCH031C-N15 | Compromised or stale remote grant | No offline protected mutation |
| ORCH031C-N16 | Duplicate staged intent after reconnect | Idempotent, reviewable reconciliation |

## Implementation gates

- **C0 Provider selection:** approved AEAD library, offline key provider and recovery policy.
- **C1 Threat model:** formal device, filesystem and attacker capabilities.
- **C2 Encrypted envelope:** schema/version, associated data and authenticated parser.
- **C3 Atomic generation store:** write, fsync, publish, crash tests on target platforms.
- **C4 Key lifecycle:** unlock, lock, rotation, recovery, zeroization where supported.
- **C5 Local-first UX:** offline indicators, safe error states, user-controlled export.
- **C6 Interoperability:** ORCH-031B migration and authenticated sync; no auto-execution.
- **C7 Independent audit:** exact-commit CI, threat-model review, cryptographic implementation review and human approval.

**Current decision:** `ORCH-031C = DESIGN_DRAFT / NO_ENCRYPTION_IMPLEMENTED / HOLD`.
