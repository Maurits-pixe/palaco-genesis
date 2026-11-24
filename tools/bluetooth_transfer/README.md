# PALACO Bluetooth Offline Transfer — v6.2 DRAFT / HOLD

Scope: exchange **Citadel** and **MUNDO** export bytes directly between devices without a cloud dependency. This directory contains an executable **transport-independent framing reference**, not a Bluetooth driver or a functioning paired-device app.

## v6.2 Ephemeral Ed25519 verifier receipt and SQLite replay chain (DRAFT / HOLD)

- `witness_scm_ci_incident.py` re-verifies the original C# SCM worker
  fault incident via the strict Python parser, then issues a **signed
  verifier receipt** under a freshly generated in-memory Ed25519 key.
  The receipt binds incident SHA-256, sequence 1, genesis predecessor,
  fixed HOLD/DENY and an entry hash. A separate public-key file allows
  verification and negative signature-key substitution tests.
- The witness saves one entry in a SQLite database with unique incident
  and entry hashes; a read-only verifier checks the signed receipt,
  contiguous sequence and previous-hash link. Existing DB, receipt or
  public key files cause admission to fail closed; no silent overwrite.
  A duplicate `attest` invocation must be rejected.
- `test_witness_scm_ci_incident.py` covers tampering, missing files,
  replacement public keys, receipt mutations, deleted entries and broken
  hash chains. GitHub Actions runs the tests under Python and validates
  the actual Windows SCM fault record with the independent witness,
  including refusal of a duplicate.
- **Trust limitation:** the verifier generates its own disposable signing
  key. It does **not** authenticate the C# producer or provide an
  independently pinned trust root. This is a *single-entry,
  run-local* SQLite ledger; deleting the ledger and key can reset replay
  history, and no hardware-backed monotonic counter or external
  witness has been established. Signed verifier receipts are **not**
  signed producer incidents, trusted timestamps, durable global
  anti-rollback guarantees or release authority.
- GO-13 HOLD / authorization DENY, Draft PR only; no production
  installation, publication, deployment or merge.

## v6.1 Independent CI incident validation and local replay rejection (DRAFT / HOLD)

- `verify_scm_ci_incident.py` independently checks incident evidence
  produced by the Windows C# SCM fault handler. It requires valid UTF-8,
  strict JSON with no duplicate, missing or unknown fields, exact
  `WORKER_FAULTED` / HOLD / DENY semantics, and the expected SHA-256 value.
- The separate Python verifier creates one exclusive, flushed local receipt
  file. Re-reading the same incident against that receipt is refused. This
  is a **local replay gate**, not a persistent or independently witnessed
  global replay ledger; deleting the receipt resets the gate.
- `test_verify_scm_ci_incident.py` covers missing evidence, duplicate JSON
  fields, missing fields, altered authorization, false signature claims,
  mismatched checksums, malformed UTF-8, oversized data and replay. The
  Windows SCM fault test checks the original incident using the separate
  Python implementation, rejects its replay and deletes the temporary
  receipt, incident and test service on completion.
- **Security limitation:** SHA-256 without a protected signing key cannot
  authenticate a producer. `independent_signature=false` remains explicit.
  This is not independent attestation, a trusted timestamp or a durable
  incident registry. No release authority, hardware TPM, BLE transfer or
  production installation is enabled.
- GO-13 HOLD / authorization DENY. PR remains Draft; no merge, publication,
  deployment or release.

## v6.0 Disposable SCM worker fault injection and incident checksum (DRAFT / HOLD)

- `--service-ci-fault` is an intentionally destructive, **test-only**
  Windows SCM mode. It requires a local temporary `palaco-ci-fault.marker`
  and the existing SCM service SID startup check. The diagnostic worker
  throws a synthetic exception after SCM starts; the supervisor emits the
  fixed `WORKER_FAULTED` incident and requests SCM stop without restart.
- `WindowsCiIncidentEvidence.cs` records the fixed non-sensitive fields
  `PALACO-BT-CI-INCIDENT-V1`, `WORKER_FAULTED`, HOLD and DENY,
  `independent_signature=false`, and a SHA-256 checksum computed over
  canonical values. The file is created exclusively and flushed to disk.
  **This checksum is NOT an authenticating signature, independent audit
  evidence, an attestation, or an authorization proof.**
- `test_scm_worker_fault.ps1` refuses non-GitHub-hosted runners,
  creates a temporary **manual-start** LocalSystem SCM service with
  `sidtype unrestricted` and explicit `failure actions=none`, checks
  Running -> Stopped after the actual worker exception, verifies that no
  automatic restart occurs, and verifies all incident fields and checksum.
  Both service and marker/evidence files are deleted in `finally`.
- The Windows CI job runs this fault injection only **after** all earlier
  Windows build, isolation, IPC and normal SCM lifecycle checks.
- **Limitations:** no external signature, trusted timestamp, independent
  incident receipt, TPM, hardware rollback defense, Android KeyMint or BLE
  transfer. This is a hosted CI test, not a production installation.
- GO-13 HOLD / authorization DENY. PR Draft; no merge, production install,
  deployment, publication or authority grant.

## v5.9 Windows worker exit supervision and incident categorization (DRAFT / HOLD)

- `WindowsWorkerSupervisor.cs` observes the diagnostic worker task. When
  a task completes unexpectedly or faults without a requested shutdown, it
  raises a fixed incident code (`WORKER_EXIT_UNEXPECTED` or
  `WORKER_FAULTED`). Deliberate cancellation produces no incident.
- `PalacoDiagnosticService.OnStart` attaches the monitor to the listener
  task. On an unexpected exit, the service records only a fixed
  `PALACO-BT-SERVICE-INCIDENT:<code>:HOLD:DENY` diagnostic line and
  requests SCM stop. Failure to request stop terminates the process rather
  than leaving a dead worker advertised as healthy. **No automatic
  worker restart, service restart, checkpoint issuance or authorization.**
- `--supervisor-self-test` checks unexpected successful completion, task
  fault and deliberate cancellation, including single-incident semantics,
  on the Windows runner. This is a deterministic unit-level proof, **not**
  an injected crash of a live SCM worker.
- **Limitations:** the incident line is not an independent, persistent or
  cryptographically signed incident ledger. SCM stop-on-fault is not yet
  verified by injecting actual worker faults under an installed service.
  Tests cannot establish continuous production supervision, TPM custody,
  hardware-backed rollback resistance or Bluetooth LE transport.
- GO-13 HOLD / authorization DENY. PR stays Draft; no merge, production
  installation, deployment or publication.

## v5.8 SCM runtime health and non-System client isolation (DRAFT / HOLD)

- `WindowsScmClientDenialTest.cs` performs an actual named-pipe connection
  attempt **while the diagnostic SCM service runs under LocalSystem**.
  The Windows CI runner's non-System token must receive Windows
  `ACCESS_DENIED`. An absent endpoint, timeout or generic I/O error is
  **inconclusive and fails the test**; simply receiving the fixed HOLD/DENY
  reply is not sufficient for this isolation test.
- The temporary hosted-runner SCM test observes that the configured diagnostic
  named pipe exists, the SCM process ID remains stable and the service remains
  Running before attempting cross-account access. It repeats these checks for
  two start/stop cycles, then deletes the test service in `finally`.
- The new `--ipc-scm-client-denial-test` command is a test-only probe with
  no BLE, TPM, import or authorization capability. The service still grants
  no release authority and never modifies checkpoints.
- **Limits:** this checks service process and pipe presence only at specific
  instants, not continuous supervision, client-role authorization, hardware
  attestation or production reliability. SCM service and LocalSystem pipe
  isolation are verified only on disposable GitHub-hosted Windows runners.
- GO-13 HOLD / authorization DENY; no merge, production install, deployment
  or publication.

## v5.7 Ephemeral Windows SCM service SID and lifecycle test (DRAFT / HOLD)

- `PalacoDiagnosticService.OnStart` now synchronously refuses SCM startup
  without the expected service SID **or** a successfully constructed protected
  diagnostic pipe. This is a startup preflight, not attestation.
- `windows_native_host/test_scm_lifecycle.ps1` uses a **disposable hosted
  Windows CI runner** to create the existing deny-only executable as a
  *manual-start*, LocalSystem SCM service with `sidtype unrestricted`.
  It checks two start/stop cycles, process identity presence and manual
  startup mode, then deletes the temporary service in `finally`.
- The Windows CI job runs the SCM test only after earlier build, ACL,
  named-pipe and cross-account tests. No production installation, service
  persistence, automatic startup or merge is authorized.
- **Important limitation:** SCM status alone cannot prove the internal worker
  remains healthy or that client-role rules are sufficient; the current
  protected pipe is account-only (LocalSystem) and no unprivileged user-facing
  path is enabled. No real TPM, hardware rollback, Android device or BLE test.
- **GO-13 HOLD / authorization DENY** remain mandatory.

## v5.6 Real Windows cross-account named-pipe rejection (DRAFT / HOLD)

- `windows_native_host/WindowsCrossAccountTest.cs` uses Windows
  `LogonUserW` to obtain an actual token for a **different local Windows
  account**. It attempts to open the same protected diagnostic pipe under
  that impersonated token. **A successful connection fails the test** even
  if the service would only answer HOLD/DENY.
- `test_cross_account.ps1` creates a temporary non-admin local account
  on a disposable GitHub-hosted Windows runner, generates a random password
  and passes the temporary credentials to the test process through environment
  variables. Its `finally` block deletes the account and clears the
  variables. No credential value is printed or committed.
- The same-account baseline before and after the negative access attempt
  still must receive fixed HOLD/DENY. The dedicated Windows CI step is
  separate from all the existing local integration, process and ACL tests.
- **Limits:** ephemeral GitHub-hosted Windows account isolation only.
  This is not a test of an installed SCM service, the specific service
  SID, a production multi-account deployment, hardware TPM, BLE transfer,
  or rollback resistance. No PALACO installation or release occurs.
- **GO-13 HOLD / authorization DENY.** PR remains Draft, no merge,
  production installation, publication or deployment.

## v5.5 Windows separate-client process and ACL negative-path audit (DRAFT / HOLD)

- `WindowsPipeProcessTest.cs` now starts a **separate diagnostic client executable process** in addition to the separate host process. The client uses `--ipc-child-client-test` exclusively for Windows CI and checks the fixed HOLD/DENY response. Both processes still run under the **same Windows account**.
- `WindowsPipeAclAudit.cs` checks that the diagnostic pipe ACL is protected and contains precisely one explicit account-SID allow rule with read/write but without permissions to change security or create pipe instances. It rejects broad FullControl, world access, inherited permissions and multiple rules.
- `WindowsPipeSecurity.cs` now fails closed if the constructed ACL does not satisfy this restrictive audit; `--self-test` runs negative ACL regressions. Existing Windows CI build, IPC integration and interrupted/restarted separate-process tests remain enabled.
- **No live second-account or lower-privilege client rejection has been proven.** Same-account SID matching, local DACL review and process separation cannot establish unique caller roles or privileged SCM service authorization. No physical TPM, rollback, Android KeyMint or BLE hardware proof is provided.
- **GO-13 HOLD / authorization DENY**; PR stays Draft; no merge, installation, publication or deployment.

## v5.4 Windows diagnostic IPC separate-process resilience (DRAFT / HOLD)

- `windows_native_host/WindowsPipeProcessTest.cs` launches the existing deny-only
  `--serve` diagnostic executable as a separate Windows process. The test
  connects with a same-account `NamedPipeClientStream`, abandons an incomplete
  framed request, waits beyond the host's five-second read deadline, and checks
  that valid requests after each interruption still receive only **HOLD/DENY**.
- The host process is terminated by the CI harness and started anew; the
  post-restart request must also receive only **HOLD/DENY**. Child process
  cleanup runs even if a test scenario fails.
- `--ipc-process-test` is a Windows-only, CI-specific mode and is invoked by
  the existing `windows-latest` workflow. It must never install or
  auto-start a Windows service; process spawning is isolated to the test mode.
- The separate-process test uses the **same Windows account** for host and
  client. It does not establish cross-account isolation, service-SID
  provisioning, independent token authority, TPM guarantees, hardware
  rollback resistance or working BLE transfers.
- All outcomes remain **GO-13 HOLD / authorization DENY**. No merge,
  installation, deployment, publication or automatic import.

## v5.3 Windows local named-pipe integration on CI

- `windows_native_host/WindowsPipeIntegrationTest.cs` starts the actual
  Windows diagnostic listener in-process on a Windows runner and connects a
  same-account client through `NamedPipeClientStream`. It checks a valid
  inspection gets only fixed **HOLD/DENY**, that an unsupported operation and
  an oversized length prefix are rejected without a response, and that a
  subsequent fresh connection is still denied.
- `--ipc-integration-test` runs this bounded Windows-only exercise; the
  dedicated `windows-latest` CI job executes it after building and the
  existing self-test.
- **Not covered:** a service installed by SCM, distinct Windows users,
  actual dedicated client roles, privilege boundaries, service restarts,
  hostile parallel processes, TPM devices, real BLE transport or Android.
  Same-account diagnostics do not imply production caller authorization.
  Windows token impersonation is attempted **after reading only the bounded
  raw frame** (maximum 1,024 bytes), and **before JSON interpretation or
  responses**: the pipe's impersonation context depends on receiving client
  traffic first. The Windows test client explicitly requests impersonation.
  All execution and publication remain **GO-13 HOLD / DENY**.

## v5.2 Windows client token and service-SID verification gates

- `windows_native_host/WindowsClientIdentityGate.cs`: the pipe server calls
  `RunAsClient` to inspect the OS-impersonated client identity and compares its
  account SID with the process-account SID; missing impersonation or mismatch
  is rejected **before** request parsing. No JSON claim can substitute for
  a Windows token. Negative-path SID matching self-checks are included.
- SCM `OnStart` now refuses startup unless the process token includes the
  expected `NT SERVICE\\PALACO-BT-Diagnostic-HOLD` service SID. This does not
  install, configure or prove provisioning of a service SID on any machine.
- This remains a **same-account diagnostic boundary**, not a dedicated
  client-role authorization policy or service-endpoint attestation. A
  same-account process can still meet the SID check; service identity
  verification at the client end, precise client role authorization, the
  named-pipe ACL, and actual SCM installation must be independently reviewed.
- No physical Windows or TPM test is run. The interface is still
  inspection-only, with all accepted requests answering **HOLD / DENY**.
  No merge, installation, BLE transfer or deployment is authorized.

## v5.1 Explicit Windows account SID pipe ACL (DRAFT / HOLD)

- `windows_native_host/WindowsPipeSecurity.cs` creates the diagnostic named
  pipe with an explicitly protected `PipeSecurity` DACL containing an
  allow rule for the **current process account SID** only. The former
  `CurrentUserOnly` flag is replaced, because .NET forbids supplying both
  an explicit `PipeSecurity` and that flag.
- `Program.cs` uses this factory and Windows `--self-test` checks that the
  restricted pipe can be created. `System.IO.Pipes.AccessControl` is
  is used through the .NET Windows-targeted framework API; no separate
  NuGet package is declared.
- **Not service-SID authorization**: the process-account SID is potentially
  shared with other processes (especially when running as LocalSystem).
  Access via the account SID does NOT authenticate an IPC peer, verify caller
  tokens, distinguish a dedicated PALACO Windows Service SID or stop
  same-user spoofing. Do not treat this DACL as sufficient for production.
- The host remains a deny-only diagnostic prototype. It has no TPM driver,
  hardware-backed replay defense, BLE link, installation procedure or
  production permission. Every successful inspection response remains
  **HOLD / DENY**.

## v5.0 Windows SCM service-host prototype (not installed)

- `windows_native_host/PalacoDiagnosticService.cs` provides a Windows
  `ServiceBase` lifecycle (`OnStart`, `OnStop`, `OnShutdown`), launched
  only by explicit `--service` mode. It reuses the existing fixed-HOLD/DENY
  inspection-only pipe handler, with cancellation on stop.
- The .NET 8 project now depends on `System.ServiceProcess.ServiceController`.
  Windows CI builds the service-capable executable and runs only the existing
  non-hardware `--self-test` checks. No service installation or elevation
  occurs in CI.
- **Critical boundary**: an SCM-compatible code path does not establish an
  installed/running service, a reviewed service SID, hardened pipe ACLs,
  authenticated IPC callers, TPM key custody, rollback protection or real BLE.
  `PipeOptions.CurrentUserOnly` currently isolates to the process account;
  under a service account this is not a user-facing IPC authorization solution.
  A dedicated Windows service SID, explicit DACLs, token checking, hardened
  install/upgrade policy, endpoint identity verification and physical tests
  are required before external clients can be admitted.
- Never install or start this draft on a production machine. Every successful
  diagnostic reply remains fixed **GO-13 HOLD / authorization DENY**.

## v4.9 Windows-only named-pipe diagnostic host (prototype)

- `windows_native_host/Palaco.Bluetooth.NativeHost.csproj` and `Program.cs` add a .NET 8 Windows-only console executable with a local named-pipe listener, `PipeOptions.CurrentUserOnly` and a 1,024-byte request cap. It parses inspection-only field shapes; the reply is always a fixed **HOLD/DENY**.
- No key material, filesystem mutation, BLE traffic, TPM access, credentials or authorization actions are implemented. The host cannot perform an import, checkpoint advance or recovery.
- A `windows-latest` GitHub Actions job builds it and runs offline parser/denial self-checks without accessing hardware.
- **Critical**: this is **not** an installed Windows Service, privileged process, authenticated cross-user RPC endpoint or production security boundary. `CurrentUserOnly` restricts user-session pipe access but does not establish service authenticity, verify caller authorization or provide hardware-backed anti-rollback. The parser's accepted JSON is not authentication; an accepted request still receives DENY.
- Future implementation requires Windows Service Control Manager integration, service SID configuration, explicit named-pipe ACL review, token impersonation/verification with minimal rights, independently verified TPM attestation and physical-device tests.

## v4.8 Windows privileged-service admission evidence inventory

- `windows_service_admission.py` correlates existing Windows IPC/native diagnostic data with an eight-control external review inventory covering service SID, named-pipe DACL, OS caller token verification, impersonation boundary, binary integrity, least privilege, session replay protection and TPM trust root.
- `test_windows_service_admission.py` adds 20 regression scenarios and is part of Bluetooth CI.
- No actual service executable, named-pipe transport, Windows token authentication, TPM operations or physical-device tests are included. Reports describing external review claims are **not authenticated evidence** or operational capabilities.
- All results remain **GO-13 HOLD / authorization DENY**, including complete externally asserted reviews.
- A native Windows implementation must establish its own privilege boundary, verify peer tokens, reject untrusted clients, and undergo independent TPM/rollback testing before any security assurance claim.

## v4.7 Windows IPC/native probe correlation (diagnostic only)

- `windows_native_correlation.py` binds a strictly decoded v4.6 inspection frame to the
  expected device identity and a separately supplied native probe snapshot.
- It compares namespace, device binding, generation and a 32-byte challenge
  across both inputs; mismatch remains HOLD/DENY. Even a fully correlated
  result **does not** verify IPC caller identity, native service provenance,
  TPM attestation, nonexportable keys or replay resistance.
- `test_windows_native_correlation.py` adds 20 regression scenarios covering
  cross-device/cross-generation substitution, wrong nonces, empty response
  digests, malformed frames and unconditional HOLD for apparently matching claims.
- An actual privileged Windows service, authenticated named-pipe transport,
  OS token verification, hardware attestation and durable replay ledger are
  **not implemented**. These remain mandatory before security claims.
- **GO-13 HOLD / authorization DENY**; no merge, deploy or automatic import.

## v4.6 Windows IPC inspection-only framing

- `windows_native_ipc_contract.py`: bounded (1024-byte maximum), canonical ASCII JSON inspection request with strict field set, 32-byte namespace, device binding and challenge, and positive generation.
- Rejects duplicate/unknown fields, unsupported operations, invalid identifiers, oversized frames and noncanonical serialization.
- `test_windows_native_ipc_contract.py`: 20 negative/roundtrip regressions wired into Bluetooth CI.
- This is **not a named-pipe server**, secure channel, caller identity verification, TPM attestation or replay defense. It processes no secrets and grants no authority. Freshness, IPC authentication, authorization, hardware custody and rollback proof remain independent native-service duties.
- **GO-13 HOLD / authorization DENY**; no merge, deployment, imports or automatic recovery.

## v4.5 Windows diagnostic intake boundary

- `windows_native_intake.py` accepts a strictly shaped Windows TPM identity,
  32-byte challenge and response digest with explicit expected-device binding.
  Its report uses a domain-separated SHA-256 diagnostic fingerprint.
- `test_windows_native_intake.py` adds 16 fail-closed regression tests
  covering wrong-device, challenge mismatch, cross-platform confusion,
  malformed probes, zero response and unconditional HOLD.
- **This is not a Windows service, authenticated IPC, TPM quote verification,
  hardware attestation, rollback-resistant storage, or BLE delivery.**
  Caller-provided challenges, identities and response digests can be forged.
  All diagnostic output is **HOLD / DENY**. It cannot unlock, mutate, import,
  release credentials or authorize deployments.
- A future native Windows service must use a separately assessed privileged
  trust boundary, measured service identity, authenticated local IPC, external
  trust-root verification and genuine physical-device rollback tests.

## Safety boundary

1. A sending device prepares an explicit resource export. Only `citadel` and `mundo` kinds are accepted. No credentials, private identity keys, signing keys, bearer tokens or execution authority should be included in an export.
2. Sender creates a fresh cryptographically random 16-byte transfer ID (32 lowercase hexadecimal characters); never reuse IDs. The adapter communicates a canonical offer, bounded to 1 MiB of data and 16 KiB per chunk.
3. The receiving user reviews the resource, sender identity, size and purpose, then explicitly consents. The receiver accepts `identity_verified=True` only from a **separate authenticated device-identity verifier**; the Bluetooth device name, MAC address and radio pairing alone are insufficient.
4. Transfer all chunks in order. The receiver rejects missing, modified, reordered, duplicated or oversized content, using a domain-separated SHA-256 integrity digest. **SHA-256 is not sender authentication or encryption.**
5. Successful reassembly returns **untrusted export bytes only**. Import requires separate schema validation, provenance/signature checks, Citadel authorization gates and user confirmation. Do not execute, publish, sync, mutate records, issue credentials or activate Citadels/MUNDO automatically.
6. Transfer sessions reject duplicates, missing frames, unexpected lengths and disconnections, and never resume automatically. An incomplete, canceled or failed transfer does not mark the ID complete; a retry must use a fresh transfer ID and a newly authenticated and approved session. The default in-memory transfer-ID replay set is lost on process restart; use the optional DurableReceiver for a local persistent receipt registry. Production must additionally protect its SQLite file against deletion, rollback, symlink swaps and filesystem tampering, authenticate the offer/digest, and define trusted-time freshness.
7. No claims of secure confidentiality: BLE link protection varies by pairing mode and platform. Production transfer must add application-layer authenticated encryption, key agreement with authenticated peer binding and device-specific secure key storage. Do not send sensitive exports before these exist.

## Protocol and testing

- `protocol.py`: offer, strict canonical JSON metadata, 16 KiB chunker, fail-closed receiver, replay guard.
- `session.py`: incremental, fail-closed session with ordered frames, explicit cancel and disconnect handling. On failure it discards retained frames; restarting requires a fresh transfer ID.
- `ble_frames.py`: BLE-GATT-value framing reference with a 7-byte header, protocol version, chunk and fragment indices, final flag, configurable bounded value size (8–512 bytes) and strict sequential reassembly. It is not a BLE radio driver, encrypted channel, authenticated link, retransmission protocol or complete transfer flow.
- `ble_sender.py`: stop-and-wait sender (at most one chunk's packets queued), caller-triggered bounded retransmission on timeout and a receiver wrapper that re-ACKs only the immediately previous, byte-identical packet without duplicate ingestion. ACKs are unauthenticated control hints; this is NOT a secure radio adapter.
- `native_platform_readiness.py`: Windows-first native hardware integration readiness evidence **inventory**, with explicit identity, capability checks and referenced external review outcomes. It produces canonical SHA-256-fingerprinted diagnostic records always marked HOLD/DENY; even all externally claimed passes do NOT authenticate hardware or authorize release. Includes Android KeyMint profile for parity. No real TPM/KeyMint implementation.
- `test_native_platform_readiness.py`: 20 negative/positive diagnostic checks for missing or failed evidence, identity mismatch, invalid references, SHA-256 changes and unconditional HOLD even for fully populated claims.
- `native_policy_review_session.py`: complete HOLD-only composition of challenged native policy/issuer pins, publisher key rotation gate, signed incident policy distribution and incident reviewer verification. Re-attests both pins around each reviewer action; any failure latches HOLD. This is not a native driver or a production trust root and has no authorizing or writing methods.
- `test_native_policy_review_session.py`: 20 end-to-end synthetic tests exercising Windows/Android identities, valid signed HOLD evidence, revocation, replay, device swapping and native/transport failures. All native signing keys in tests are ephemeral software keys.
- `native_policy_custody.py`: explicit Windows TPM / Android KeyMint **integration contract**, requiring a separately pinned Ed25519 native attestation key, native-provisioned platform/device identity and freshly challenged coherent pair of incident-policy and publisher-key revision+digest pins. Fail-closed sticky HOLD on mismatch, stale challenge, changed pin or outage. Read-only pin views feed existing policy gates; this Python module does NOT implement TPM/KeyMint, attest secure hardware, or enforce protected monotonicity.
- `test_native_policy_custody.py`: 20 synthetic tests with ephemeral software key, checking platform/device/generation binding, nonce replay, issuer+policy changes, signature failures and sticky HOLD.
- `publisher_rotation_gate.py`: opt-in policy-publisher key rotation gate with a **separately protected** monotonic publisher revision+canonical digest pin. Verifies the issuer allowlist and revoked flags before/after each signed-policy read. Old instances latch HOLD on rotation, fresh instances require matching protected issuer registry and pin; the incident-reviewer gate STILL separately requires its own protected *incident policy* pin. All external protected providers are protocol dependencies, not implemented native hardware.
- `test_publisher_rotation_gate.py`: 20 synthetic tests for signer rotation, old-key revocation, stale pins, issuer-source outages, key tampering, version races, reviewer-gate integration and explicit fake dual-store rollback bypass.
- `signed_policy_distribution.py`: read-only Ed25519 verified incident-policy distribution adapter requiring independently pinned publisher public keys. Canonical policy revision, exact content digest and issuer ID are domain-bound in the publisher signature; `VerifiedSignedPolicySource` supplies the versioned review gate while its separate protected `PolicyPin` still blocks replay of old signed policies. No publisher private keys, native trusted key enrollment, protected revocation or real monotonic hardware are provided.
- `test_signed_policy_distribution.py`: 20 synthetic tests for forged policy edits, signer swaps, time/policy gate integration, revision replay, signed updates, and an explicit unprotected dual-policy-and-pin rollback bypass.
- `versioned_incident_policy.py`: optional fail-closed live policy source with external monotonic revision+canonical digest pin, rejecting changed/revoked roles or stale versions on every signer/reviewer decision. A mismatch permanently denies within that gate instance; a new instance must compare against the independently protected current pin. The external protected source and pin are protocols only, no hardware or authenticated native implementation.
- `test_versioned_incident_policy.py`: 20 in-memory fake-policy regressions for revision bump, revocation, outdated sources, outages, role/clock checks and explicit dual-store rollback bypass.
- `incident_reviewer_registry.py`: opt-in **externally provisioned** role/validity/revocation policy for signed HOLD evidence. Immutable in-process snapshot separates incident evidence signers from inspection-only reviewers; requires a separately trusted clock and pinned public keys. Snapshot changes do NOT propagate revocations automatically; secure policy distribution and hardware provisioning remain unimplemented. It never authorizes repair, recovery, import or release.
- `test_incident_reviewer_registry.py`: 22 regression tests for signer/reviewer separation, key revocation, expiration, clock failure, wrong signatures, nonce mismatches and stale snapshot constraints.
- `signed_fencing_incident.py`: Ed25519 verification for HOLD-only incident reports, with an exact reviewer-supplied 32-byte challenge, canonical report bytes, signer ID and independently pinned 32-byte public key. Provides only detached signature attachment/verification: private-key storage, protected provisioning, revocation, signed identity/role policy and hardware attestation are NOT implemented. A signature proves only signing-key possession, not truth of the incident source.
- `test_signed_fencing_incident.py`: 16 synthetic tests using ephemeral Ed25519 keys, nonce replay rejection, signer substitution, signature tampering and perpetual HOLD/DENY on valid signatures.
- `fencing_incident_evidence.py`: read-only incident evidence for SQLite vs independent witness, with canonical JSON and domain-separated SHA-256 fingerprint. Captures scope, fencing epoch, HOLD flags, checkpoint count/content roots and witness revision; status is match, mismatch, changed_during_read or unavailable. Every report sets HOLD + authorization DENY, including matches; no repair or unhold action. Fingerprint is NOT a signature or trusted provenance.
- `test_fencing_incident_evidence.py`: 16 synthetic tests for split commits, incident tampering, racing snapshots, outages, deterministic canonicalization and unchanged source stores.
- `file_witness_fixture.py`: explicitly UNTRUSTED file-backed JSON witness test fixture (atomic rename and fsync, no protected monotonicity or cross-process trusted CAS). Never install in production.
- `witness_crash_probe.py`: test-only child process that terminates immediately after the witness write, before the SQLite transaction.
- `test_witnessed_sqlite_crash.py`: 9 subprocess crash/persistence/HOLD regressions, including witness-first partial CAS/incident commits and a deliberate dual-unprotected-store rollback bypass.
- `witnessed_sqlite_fencing.py`: opt-in integration requiring an independent monotonic and protected witness of full SQLite fencing state: 32-byte namespace, witness revision, fence epoch, incident HOLD, count and content root. Checks all fields on initial opening, reads, CAS updates and incident latch. Witness advances first: a non-atomic split-commit leads to HOLD and never auto-repairs. This code supplies no real protected witness backend.
- `test_witnessed_sqlite_fencing.py`: 26 integration tests with mutable fake witness and real SQLite file, checking checkpoint rollback, same-count substitution, direct-SQL incident erasure, epoch tampering, uncertain writes and fake dual-store rollback limitation.
- `fencing_process_probe.py`: local-only subprocess driver for test isolation, process crashes and SQLite lock contention; not a user or production administrative interface.
- `test_sqlite_fencing_multiprocess.py`: 14 actual independent-Python-process regressions for stale CAS conflict, committed/uncommitted process crashes, incident persistence and lock contention. Includes a direct-SQL tampering counterexample. These are cooperative local SQLite tests, not native hardware security.
- `sqlite_fencing_reference.py`: **real SQLite-backed development reference** for the native fencing protocol. A single-row SQLite transaction with BEGIN IMMEDIATE performs epoch/incident/checkpoint compare-and-advance atomically for cooperating clients on the same database file; `latch_incident` atomically increments the epoch and persists HOLD. Supports explicit new vs existing registry and refuses silent recreation or wrong namespace. The database is NOT trusted against attacker modification, removal, copy or rollback; this is NOT TPM, KeyMint or production authorization.
- `test_sqlite_fencing_reference.py`: 22 file-backed tests for concurrent connections, restart persistence, incident epoch revocation, stale CAS, corrupted records and an explicit unprotected SQLite rollback counterexample.
- `native_fencing_gate.py`: optional privileged native atomic-fencing service contract requiring a single transactional snapshot with namespace, fencing epoch, incident HOLD status and checkpoint content. The `FencedChallengeAnchor` rejects revoked epochs, active incidents, stale CAS inputs, invalid transitions and uncertain native writes. Cross-process atomicity and secure persistence MUST be implemented by the native service; Python cannot enforce them.
- `test_native_fencing_gate.py`: 22 synthetic regressions including competing writes, revocation just before CAS, stale epochs, uncertain acknowledgements and an intentionally vulnerable fake-backend rollback case.
- `durable_hold_gate.py`: optional native protected-incident-store interface with 32-byte namespace binding, monotonic incident sequence, sticky HOLD after checkpoint failure, and denial on reopening when incident HOLD is recorded. Uses a native `read` and `latch` contract; no reset or automatic recovery method. A missing or untrustworthy store denies access. The store itself is NOT implemented and software cannot guarantee true persistence if incident latching fails or a backend is compromised.
- `test_durable_hold_gate.py`: 30 synthetic incident-store outage, incident-race, malformed-checkpoint, serialized-thread, restart denial, uncertain write, namespace and fake-backend rollback tests.
- `independent_checkpoint_witness.py`: optional independent protected witness for native challenge checkpoint states, using a namespace-scoped monotonic revision and full content root. Every read compares native and witness checkpoints; on write, the protected witness must advance first, followed by native state. Nonatomic cross-store failures remain HOLD; no auto-repair. The independently protected witness backend is NOT provided.
- `test_independent_checkpoint_witness.py`: 24 synthetic regressions including sticky-HOLD, restart bypass limitations, native-only rollback, consumed-bit reactivation, missing witness, mismatched namespaces, concurrency-like faults, uncertain writes and a documented both-fakes-rollback limitation.
- `attested_native_checkpoint.py`: optional nonce-bound Ed25519 verification of a privileged native service's platform identity and checkpoint snapshot. Each read uses a fresh 256-bit challenge and verifies an independently pinned signing key, 32-byte namespace, device binding, platform, generation, count, and root. Writes require freshly attested matching before/after states. Does not provide TPM/KeyMint hardware key custody or actual anti-rollback.
- `test_attested_native_checkpoint.py`: 20 regressions with genuine ephemeral Ed25519 keys and an untrusted software-only fake native signer, including tamper, wrong device, replayed challenge, CAS failures and validly signed rollback demonstration.
- `platform_checkpoint_bridge.py`: distinct Windows TPM and Android KeyMint privileged native service bindings. Checks a provisioned immutable platform, 32-byte device binding, namespace and generation before and after native operations. Uses the existing scope-bound CAS checkpoint adapter. This is an integration contract ONLY, not actual TPM, WinRT, Android KeyMint or StrongBox calls, device attestation or real rollback protection.
- `test_platform_checkpoint_bridge.py`: 20 synthetic platform mismatch, device/namespace/generation swap, outage, partial write and fake-backend rollback scenarios.
- `native_checkpoint_scope.py`: explicit 32-byte storage namespace bound to a privileged native checkpoint backend. Verifies namespace and checkpoint contents on read, checks CAS preconditions and confirms post-write contents; rejects switched namespaces, failed writes and unconfirmed results. Contract only, not hardware attestation or rollback-resistant storage.
- `test_native_checkpoint_scope.py`: 18 synthetic namespace, checkpoint transition, backend outage and tamper tests. Includes a deliberate demonstration that a fake backend can still be rolled back.
- `test_anchored_review_intake.py`: 16 real Ed25519 integration regressions for the explicitly selected anchored challenge ledger, no silent legacy fallback, consumed-state rollback, expiry, concurrent submissions and uncertain checkpoint advancement.
- `anchored_challenges.py`: opt-in single-database challenge writer with canonical SHA-256 commitment of the complete ledger, including token, evidence hash, reviewer, timestamps and consumption state. Compares each transaction against an independently trusted `(count, root)` anchor, commits an external CAS checkpoint while holding SQLite `BEGIN IMMEDIATE`, and fails closed on mismatches or uncertain updates. SQLite and the anchor cannot commit atomically; failures require supervised HOLD. This does not create real secure external storage or protect against arbitrary uncooperative DB writes.
- `test_anchored_challenges.py`: 20 synthetic tamper, rollback, concurrency and checkpoint-fault regressions; the fake anchor is deliberately not secure.
- `review_intake.py`: includes the separate `AnchoredRecoveryReviewIntake` composition for an explicitly supplied independently protected challenge anchor; never selects the unanchored ledger when this constructor is used. Legacy `RecoveryReviewIntake` remains for compatibility and MUST NOT be used for security-sensitive native production.
- `review_intake.py`: offline HOLD-only end-to-end integration of root-signed reviewer policy, externally anchored root/revision state, real Ed25519 reviewer signature checks, and SQLite one-time challenge consumption. It intentionally contains no repair/import/approval methods.
- `test_review_intake.py`: 20 end-to-end tests with genuine ephemeral root/reviewer keys, expiry, replay, concurrency, key revocation, policy changes and anchor changes during signature verification.
- `protected_policy_gate.py`: external trusted root/revision **snapshot** interface and a fail-closed wrapper around real Ed25519 policy/reviewer verification. Re-reads the privileged anchor for every reviewer verification and DENIES if the root or revision differs, or the anchor is missing. Does not store or authenticate the anchor itself.
- `test_protected_policy_gate.py`: 18 synthetic tests for root rotation, version change, missing anchor and explicit rollback limitation.
- `signed_reviewer_policy.py`: load a canonical offline reviewer roster **only after** verifying a genuine Ed25519 signature by an independently pinned root public key and checking that the signed policy version equals a trusted externally anchored revision. Signed revocation/rotation and validity windows feed the real Ed25519 reviewer verifier. The root key, expected revision and clock MUST be supplied from protected native sources; no such storage or enrollment exists here.
- `test_signed_reviewer_policy.py`: genuine signed test fixtures for revocation, version rollback, key rotation, modified rosters and canonical representation.
- `ed25519_review_verifier.py`: genuine Ed25519 signature validation via the `cryptography` package, using an explicit snapshot of trusted reviewer public keys with required `recovery_reviewer` role, nonrevoked status and trusted UTC validity window. The native trusted service must provision and protect keys, revocation evidence and clock independently; none are fetched from BLE or user-controlled input.
- `test_ed25519_review_verifier.py`: 24 tests using ephemeral Ed25519 keypairs, tampering, revocation, role, expiry and registry validation.
- `review_challenges.py`: opt-in SQLite-backed 256-bit random challenge issuance with short trusted-UTC expiry, reviewer/evidence binding and atomic one-shot consumption after externally verified reviewer submission. The SQLite file is not anti-rollback or tamper-proof; a protected native storage boundary and trusted clock remain required.
- `test_review_challenges.py`: 20 synthetic expiration, replay, concurrent-submit, identity/evidence binding and registry-failure tests.
- `signed_review_gate.py`: HOLD-only review-intake contract binding exact canonical recovery evidence to a fresh challenge and a reviewer key identifier; requires trusted external signature, role and revocation verification, with no signing keys, trusted verifier or repair authority provided.
- `test_signed_review_gate.py`: 20 negative and positive synthetic review gate scenarios using a deliberately non-cryptographic fake verifier.
- `recovery_evidence.py`: immutable canonical JSON diagnostic envelopes with domain-separated SHA-256 checksums. The envelope exposes only status, bounded counters and root hashes; the decision is always HOLD, even for MATCH. A checksum detects incidental changes but is not a signature or cryptographically authenticated provenance.
- `test_recovery_evidence.py`: 20 regression cases for stable evidence, altered decisions, mismatched status, read-only behavior and no plaintext payload leakage.
- `serialized_receipts.py`: opt-in `SerializedContentReceiver` with SQLite `BEGIN IMMEDIATE` to serialize cooperating writers across processes on the SAME local database. Checks the content checkpoint inside the lock; validates data, inserts the receipt, advances the trusted external checkpoint, then commits SQLite before returning bytes. Cross-store atomicity is NOT achievable here: anchor-ahead crash failures require manual HOLD, and a test double cannot enforce trust. No automatic recovery.
- `test_serialized_receipts.py`: concurrent same/different IDs, partial checkpoint commit, insertion failures, tamper and fail-closed regressions.
- `recovery_inspection.py`: strictly read-only SQLite recovery diagnostic, classifies MATCH / DATABASE_AHEAD / ANCHOR_AHEAD / CONTENT_MISMATCH / UNAVAILABLE. It does not initialize databases, change receipt rows, advance anchors, authorize imports, or resolve a HOLD. Native app must keep transfers blocked until independently reviewed evidence supports recovery.
- `test_recovery_inspection.py`: 20 synthetic read-only diagnostics, tamper detection and fail-closed tests.
- `receipt_integrity.py`: optional SHA-256 content commitment of all completed receipt IDs and payload hashes in canonical order, checked against an independent trusted `(count, root)` anchor. A matching count alone is insufficient; same-count row substitution and changed hashes are detected when the external root is genuinely protected. Single-writer prototype only; no actual secure anchor included.
- `test_receipt_integrity.py`: 19 synthetic tamper, rollback, mismatch and interrupted-checkpoint regression cases.
- `replay_checkpoint.py`: optional external monotonic counter admission contract. It compares an independently protected receipt count with SQLite's row count, and refuses to return newly received bytes unless the database receipt and counter advancement both complete. The reference supplies **no** trusted hardware counter. A crash between the two stores will deliberately cause HOLD until authorized recovery.
- `test_replay_checkpoint.py`: synthetic external-counter tests for rollback, mismatches and storage faults, including a test demonstrating that same-count record substitution remains undetectable.
- `durable_replay.py`: opt-in SQLite-backed durable completed-transfer registry. Unique transfer IDs are claimed atomically after payload validation and before returning bytes. It rejects duplicate completed IDs after restarts, missing/corrupted databases during a running process, and registry capacity exhaustion (100,000 entries). It requires an absolute path in an existing trusted local directory. It is not encrypted, tamper-evident, rollback-resistant or a replacement for authenticated sender identity.
- `test_durable_replay.py`: persistence, duplicate prevention, schema corruption, validation, and commit-failure regressions.
- `send_watchdog.py`: caller-polled stop-and-wait sender ACK deadline (default 5s), bounded retry and total deadline (default 600s), with fail-closed monotonic clock validation. No actual timers, radio, identity or encryption.
- `test_send_watchdog.py`: 19 synthetic ACK deadline and clock regression cases.
- `receive_watchdog.py`: caller-driven monotonic idle and total deadlines, fail-closed clock checks, no automatic resumption. The native adapter MUST call `poll()` from a reliable scheduler even when no notifications arrive. Duplicate frames do not count as progress. Timeouts do not supply identity or revocation evidence.
- `test_receive_watchdog.py`: 20 deterministic deadline and clock-failure regression cases.
- `native_adapter_contract.py`: one-shot native receive-controller interface: begin, GATT notification, complete, disconnect, permission_revoked, abort; explicit IDLE / RECEIVING / RECEIVED_UNTRUSTED / ABORTED state model. It is an integration harness and contains NO radio implementation.
- `test_native_adapter_contract.py`: 17 mocked lifecycle test cases including cancellation, invalid binding, corruption and replay.
- `transport_gate.py`: fail-closed native-adapter admission contract requiring independently verified, authenticated, encrypted peer context and a bound offer. Mock boolean evidence is NOT cryptographic proof. No connection, keys or encryption are implemented.
- `test_transport_gate.py`: synthetic positive/negative admission-gate checks.
- `test_protocol.py`, `test_session.py`, `test_ble_frames.py`, and `test_ble_sender.py`: Python standard-library regression suites; no Bluetooth hardware required.

Run from this directory:

```sh
python -m unittest -v test_protocol.py test_session.py test_ble_frames.py test_ble_sender.py test_transport_gate.py test_native_adapter_contract.py test_receive_watchdog.py test_send_watchdog.py test_durable_replay.py test_replay_checkpoint.py test_receipt_integrity.py test_recovery_inspection.py test_serialized_receipts.py test_recovery_evidence.py test_signed_review_gate.py test_review_challenges.py test_ed25519_review_verifier.py test_signed_reviewer_policy.py test_protected_policy_gate.py test_review_intake.py test_anchored_challenges.py test_anchored_review_intake.py test_native_checkpoint_scope.py test_platform_checkpoint_bridge.py test_attested_native_checkpoint.py test_independent_checkpoint_witness.py test_durable_hold_gate.py test_native_fencing_gate.py test_sqlite_fencing_reference.py test_sqlite_fencing_multiprocess.py test_witnessed_sqlite_fencing.py test_witnessed_sqlite_crash.py test_fencing_incident_evidence.py test_signed_fencing_incident.py test_incident_reviewer_registry.py test_versioned_incident_policy.py test_signed_policy_distribution.py test_publisher_rotation_gate.py test_native_policy_custody.py test_native_policy_review_session.py test_native_platform_readiness.py
```

### Device integration plan

- **Windows/Android native adapter:** BLE GATT service with a versioned service UUID, verified negotiated GATT application-value size, transport-specific ACK/retransmission policy, backpressure and cancel support. The framed bytes MUST remain within the negotiated value limit; BLE ATT MTU itself is not the same thing as the usable GATT value size. Keep the adapter outside the trusted core.
- **Browser:** Web Bluetooth can act as a BLE GATT client in supported secure-context browsers, but cannot be assumed to provide a browser-to-browser generic file-transfer server. Browser support and platform permissions must be checked; provide native-app or QR/local-file export fallback.
- **iOS:** requires a platform-specific Core Bluetooth implementation and relevant platform permissions. No claim of background operation.
- **Offline:** never require an internet server to send or verify framed bytes. External identity/revocation evidence must be locally available and within its specified freshness policy; unknown evidence => HOLD.
- **Interoperability:** add real-device tests for disconnect/reconnect, peer impersonation, forged metadata, MTU changes, permission denial, battery exhaustion, duplicate packets, power loss and encryption handshake before release.

**Integration rule:** Never accept `VerifiedTransportEvidence` built from a JSON request, app UI field, radio-visible name, or unauthenticated callback. These flags must be produced only by a dedicated, verified native security adapter. The digest only establishes offer equality; it is not a MAC, a signature, or an identity proof. For live hardware, bind the peer public key, transport key, session nonce, and offer to an authenticated handshake, and require explicit user confirmation.

**Native integration gate:** A production Windows WinRT or Android BluetoothGatt adapter must independently authenticate the peer and session, establish application-layer encryption, securely bind the exact offer and user consent, and feed the resulting verified evidence only via trusted code. The current controller has no hardware access and can be bypassed by forged evidence if exposed to an untrusted caller. Do not ship until this trust boundary is enforced with device tests.

**Timeout policy:** Default idle timeout 15 seconds and total timeout 600 seconds; accepted bounds are idle 1–120 seconds and total 1–3600 seconds. The watchdog requires an external trusted monotonic clock; it does not schedule timers itself. Never use wall-clock time for elapsed-time policy and never treat this as a trusted timestamp or revocation check.

**Send timer contract:** The native adapter writes the frame returned by `start()`, schedules monotonic `poll()` even in radio silence, sends frames returned by `poll()` on timeout, and writes the next frame returned by `acknowledge()` only after receipt of an independently authenticated ACK. The reference does not actually authenticate an ACK or send bytes over Bluetooth. Invalid clocks and elapsed deadlines cancel the session.

**Serialized writer policy:** `SerializedContentReceiver` is a separate opt-in single-database writer contract for cooperating processes. It acquires a SQLite RESERVED writer lock (`BEGIN IMMEDIATE`) before comparing the trusted content root and inserting a new validated receipt. It advances the independently protected anchor before the SQLite transaction commits; under a crash or uncertain anchor write, checkpoint/DB divergence yields HOLD. No automatic repair and no import authorization. A second process that bypasses this contract, DB-file replacement, or an untrusted external anchor remains outside the guarantee. The older `ContentAnchoredReceiver` remains a single-writer reference and is not automatically upgraded.

**Review challenge storage:** The privileged native service must own the newly created registry and trust its UTC clock. A challenge is 32 bytes from `secrets.token_bytes`, expires after 300 seconds by default (configurable 1–3600 seconds), and is linked to a reviewer key ID plus the recovery evidence fingerprint. On valid externally verified intake, a SQLite write lock serializes single-use consumption even across cooperating processes. It does not prevent replays after malicious DB rollback or clock rollback; production requires independently anchored anti-rollback state, trusted time, authenticated reviewer credentials and an operational key-revocation process. No automatic recovery is possible.

**Native platform acceptance evidence (v4.4):** `inspect_native_readiness` produces a strict Windows-first (Android-capable) inventory of eight independently reviewed hardware security criteria: privileged service identity, hardware device binding, nonexportable keys, independent monotonic pin, restart rollback test, atomic CAS, replay/tamper rejection and trusted root provisioning. The resulting diagnostic is always HOLD/DENY and is not cryptographic verification of the input claims. Real native integration, hardware tests and protected proof collection remain unimplemented.

**Native policy-to-review composition (v4.3):** `NativePolicyReviewSession` wires a challenged native two-pin reader to the signed issuer-key/incident-policy pipeline, with pre/post observations and sticky fail-closed HOLD. Both platforms are simulated in integration tests, NOT exercised on real devices. Even a valid signed incident provides only evidence verification and reviewer inspection eligibility, never unlock, recovery, import or deploy. True antirollback and publisher custody still require privileged native services.

**Native policy custody boundary (v4.2):** `AttestedNativePolicyPins` checks a challenged, Ed25519-signed observation of Windows/Android native identity plus BOTH monotonic policy pins. Two read-only pin views can be plugged into the incident-reviewer and publisher rotation gates. Changed identity or pins cause a sticky per-instance HOLD; no auto-enrollment, pin advancement or recovery. A pinned software key can generate the same valid-looking signature: secure hardware custody and antirollback must be independently proven by privileged platform integration, which is not supplied.

**Publisher key rotation (v4.1):** `RotationPinnedPolicySource` adds a separate protected publisher-key policy registry with monotonic revision+digest pin and explicit revoked flags. It rechecks the publisher policy around each signature verification. Rotated publisher sets invalidate existing instances; a new instance only recognizes active publishers in the currently pinned set. Hardware-backed native publisher custody, authenticated revocation distribution and genuine anti-rollback pin are NOT implemented, and a mutable fake source plus mutable fake pin can both be rolled back. This remains HOLD-only and cannot authorize imports or release.

**Ed25519-signed policy transport (v4.0):** `VerifiedSignedPolicySource` verifies signed canonical snapshots on every read using separately installed policy-publisher public keys. The reviewer gate still requires the independent monotonic revision+digest pin; **signed data alone is replayable**. Real publisher enrollment, protected signing keys, attested time, native policy store and secure pin/rollback enforcement are NOT implemented. The tests use temporary keys and mutable local fakes. A new signed policy permits only HOLD-only incident review, not import, unlock, recovery, execution or publication.

**Monotonic incident policy pin (v3.9):** `VersionedIncidentReviewerGate` rechecks a protected policy source against a separately provisioned monotonic `(revision, canonical SHA-256 digest)` pin before every signature or inspection eligibility check; it latches local HOLD on mismatches or outages. A new policy revision invalidates prior instances; only a newly constructed instance with matching protected inputs can continue HOLD-only inspection. These external protected services are NOT supplied. An attacker who can roll back both fake policy and fake pin can fool a new instance, explicitly tested. No durable native policy store, secure clock, trusted distribution or recovery authority.

**Reviewer/signer policy gate (v3.8):** `IncidentReviewerRegistry` enforces pinned public keys, strict signer/reviewer roles, revoked flags and trusted-clock validity windows. Valid incident signatures are verifiable only under the incident-signer role, and reviewer eligibility is inspection-only with HOLD/DENY. This is a frozen snapshot: revoking a key in a policy registry requires secure distribution of an updated version; pre-existing instances do not automatically learn about the revocation. Real secure key custody, native clock and protected monotonic policy versions are not supplied.

**Signed incident review (v3.7):** The optional signed-envelope verifier accepts a detached Ed25519 signature bound to the exact canonical HOLD-only incident evidence, signer identity and 32-byte nonce supplied independently by the reviewer. It checks against an independently pinned public key. This is not signer enrollment, role authorization, hardware-backed attestation, trusted provenance, recovery or release approval. The nonce needs a genuinely fresh, reviewer-controlled source and must not come from a BLE peer or the signing service. All reports preserve HOLD/DENY.

**Read-only incident evidence (v3.6):** `inspect_fencing_incident` double-reads local SQLite and external witness snapshots for reviewer-facing diagnostics without writing either store. It emits canonical HOLD-only data with a SHA-256 fingerprint; `verify_fencing_incident_evidence` checks canonical consistency and hash only. This does not prove the source is independent, securely stored, accurate, or signed; the report never confers import, recovery, unlock or execution authority. Concurrent changes and unavailable stores remain HOLD.

**Cross-process witness crash injection (v3.5):** A new untrusted file-backed witness fixture and subprocess crash probe test the exact interruption window after witness update but before SQLite commit. Reopening with a full protected witness would deny the mismatched state; tests verify that the current coordinator denies this state with the development fixture. This fixture only persists JSON using file replacement and fsync; it is NOT independently secured or protected from malicious edits, and a dual-store rollback remains undetectable. No repair/authorization is added.

**Witnessed transition hardening (v3.4):** The optional witness/SQLite coordinator now rejects count jumps, same-state writes, mismatched epochs, held incidents and foreign namespaces **before advancing the external witness**, avoiding preventable split-commit incidents caused by invalid requests. A process-local RLock serializes calls on the same coordinator instance. It does not serialize separate instances/processes or make the witness+SQLite write atomic: a crash between commits still requires HOLD and offline review. Regression tests include invalid-transition no-witness-write guarantees, local concurrency and interrupted writes.

**Witness-bound SQLite fencing (v3.3):** `WitnessedFencingService` composes the SQLite development service with a separately pinned external `(namespace,revision,epoch,HOLD,count,root)` witness. A fresh instance denies when a protected witness and local database disagree, including after incident tampering or rollback. External witness writes precede SQLite, so failures can leave intentional HOLD and require authorized manual reconciliation. The included fake witness is not secure; resetting BOTH the local DB and fake witness can erase all evidence. No trusted native witness hardware/API, cross-store atomic commit, production device security or automatic repair exists. The wrapper is opt-in and does not replace production trust boundaries.

**Actual cross-process tests (v3.2):** The SQLite reference is now exercised by separate Python interpreter processes, not just threads. Tests check one-winner CAS, crash before/after commit, lock contention, durable SQLite incident visibility, and intentionally demonstrate that direct SQL can erase the unprotected HOLD row. No native device verification, TPM/KeyMint, protected persistence, peer authentication or secure hardware. The regression subprocess probe must never be installed as a privileged application command.

**SQLite fencing development reference (v3.1):** An executable `SQLiteFencingReference` now implements the same atomic fencing API over a real file-backed SQLite database, including incident latching and epoch invalidation. It is useful for integration and concurrency regression tests, but SQLite is *not* a protected native backend: a caller with file access can roll back the entire database, rewrite HOLD or replace the file. It is not an authorized security service and MUST NOT be used to satisfy hardware anti-rollback or trusted-root requirements. Real TPM/KeyMint and external witness integration remain required.

**Native atomic fencing (v3.0):** A separate optional `FencedChallengeAnchor` requires privileged native `read` and `compare_and_advance` methods. The native side must check the fence epoch, protected incident HOLD and exact checkpoint CAS **atomically** across every process sharing the namespace, then durably commit the new state. The Python wrapper detects changed/held epochs and refuses uncertain writes but does not supply the atomic service, hardware monotonicity, durable incident backend or genuine anti-rollback. A compromised fake service may return to an old state and fool a brand-new instance; explicit regression confirms this limitation. This is not silently integrated with the legacy review intake.

**HOLD concurrency hardening (v2.9):** The opt-in durable incident gate now uses a process-local reentrant lock to serialize calls on that exact instance, validates checkpoint tuple shape and count/root transition before forwarding writes, and rechecks the incident status after reads and writes. A concurrent external HOLD detected during an operation denies further local use. This is NOT an atomic native cross-process fencing protocol: a remote/native incident can still race with a privileged checkpoint write, and there is no cryptographic secure clock, protected hardware incident store or signed fencing lease. Native integration MUST provide such serialization/fencing and trustworthy durable incident latching.

**Restart incident HOLD (v2.8):** `DurableHoldChallengeAnchor` is an opt-in wrapper for a checkpoint anchor plus an independently protected, monotonic and sticky incident register. It checks the register before/after operations and latches HOLD on a failed native checkpoint read/write. A later instance refuses to open if the incident bit is protected and remains set. It cannot persist a marker when the incident service itself is down; the running instance still fails closed, but a restart guarantee requires a real native protected store with verified availability, durability and recovery rules. The mock store can be rolled back and is not secure. No automatic clearing or authorization is implemented.

**Sticky incident HOLD (v2.7):** The `WitnessedChallengeAnchor` now latches a fail-closed HOLD in the current object after a failed read, inconsistent checkpoint or uncertain witness/native write. A later apparent match cannot silently clear that instance's latch; read and advance remain denied. This is **not persisted across process restarts** and does not stop a caller from constructing a new object against matching but compromised stores. Native production MUST add a separate tamper-resistant durable incident latch and explicit authorized recovery. Never interpret an in-memory latch alone as protection against rollback or restart bypass.

**Independent monotonic witness:** `WitnessedChallengeAnchor` composes an already verified native checkpoint anchor (including signed snapshots if used) with an independently owned `(namespace,revision,count,root)` checkpoint witness. A content-root change without a count increase must still increment the witness revision. The witness is advanced before the native store; a crash between stores causes intentional HOLD, without automatic rollback. The contract is only effective when the second service has genuinely independent and protected monotonic storage. The included fake witness is mutable and a same-attacker rollback of BOTH stores is explicitly shown to evade detection. An external trustworthy backend and audited crash recovery are not implemented. This optional wrapper can be passed to `AnchoredRecoveryReviewIntake` by trusted native code.

**Signed native checkpoint snapshots:** `bind_attested_native_checkpoint` requires a separate, **independently provisioned** Ed25519 public key for the native checkpoint signer. It requests a new random challenge per read and verifies the signature across exact device identity and checkpoint state. This detects forged replies or stale replayed attestations if the native signer key is protected and the challenge remains unpredictable. Crucially, a compromised signer or unprotected native storage can sign a rolled-back state; this is not hardware/device attestation, secure monotonic storage, rollback proof, native Bluetooth, or a deployed Windows/Android driver. Key enrollment and trust anchoring are not implemented. Never accept the public key from the same untrusted response being verified.

**Windows / Android native service contract:** The Windows TPM path requires a privileged TPM-backed native service that can authenticate device identity and implement atomic scope-bound monotonic checkpoint CAS. Windows DPAPI or ordinary encryption at rest alone does not provide anti-rollback. The Android path requires an independently audited KeyMint/StrongBox integration with proven rollback-resistant state semantics; merely storing a key in Android Keystore does not prove a monotonic counter or atomic CAS. These backend services and secure provisioning are NOT in this repository. The Python interface checks claimed native identity but cannot authenticate claims sourced from a compromised service. Never expose these bridge constructors to untrusted UI or peer parameters.

**Native checkpoint binding:** `ScopeBoundChallengeAnchor` implements the existing `(count, root)` anchor protocol by relying on an externally privileged native backend that reports an immutable 32-byte storage namespace, current count, and content root. The adapter validates an explicit expected namespace and rechecks state after a CAS write. Native backend security (atomic scope-bound CAS, integrity, trusted provisioning and true anti-rollback storage) is NOT implemented; a local fake may be reset to a prior checkpoint and pass. The 32-byte namespace is a binding identifier, NOT a secret or authentication credential. This is an optional adapter that can be passed to `AnchoredRecoveryReviewIntake` by trusted native code, not a default driver.

**Anchored intake integration:** `AnchoredRecoveryReviewIntake` requires an explicit `(count, SHA-256 root)` ledger anchor, checks the root-signed Ed25519 reviewer policy, and uses the anchored SQLite challenge ledger for both issuance and submission. It does not fall back to the unanchored ledger if the anchor is missing or offline. All success is HOLD_REVIEWABLE. The older `RecoveryReviewIntake` still exists only as a compatibility reference. This is not secure hardware storage, and cross-store commits may leave HOLD following power loss.

**Anchored challenge ledger:** `AnchoredChallengeLedger` is an opt-in alternative to the original SQLite challenge registry. It binds all existing rows including consumed-state to an external protected compare-and-advance `(count, SHA-256 root)` checkpoint and rejects record replacement, reactivation and rollback relative to that state. This still does NOT provide protected hardware anchoring, atomic cross-store commits, safe automatic crash recovery, or trusted key provisioning. On partial failure the registry remains HOLD. The integrated `RecoveryReviewIntake` continues using its existing registry unless explicitly adapted by privileged native code; it has not been silently upgraded.

**Integrated review intake:** `RecoveryReviewIntake` composes existing signing, key-policy, external anchor and replay gates. For new ledgers, registry creation is an explicit opt-in; default reopening refuses missing registries. Submission returns `HOLD_REVIEWABLE` only, never recovery authorization. The anchor is now rechecked before AND after reviewer signature verification; this rejects observable mid-verification rotation but is not an atomic native security lease. All test keys are ephemeral, and the test anchor is mutable and unprotected. Real independent protected root/revision state, anti-rollback challenge storage and native secure key custody remain necessary.

**Protected anchor integration:** `AnchoredReviewVerifier` accepts an external atomic `(root_public_key, revision)` reader and rejects root/revision changes between loading a policy and checking each reviewer signature. It cannot authenticate the reader or prevent its rollback. A fake that reverts to a previous pair passes again; only native protected monotonic storage with secure provisioning can close this gap. Existing trusted clocks, protected challenge registry and runtime revocation updates also remain external obligations. An anchor mismatch never triggers recovery or approval.

**Root-signed reviewer policy:** The root public key must be pinned outside attacker-writable policy data. The external trusted revision must advance when a new signed policy is authorized; otherwise older signed policies can remain acceptable. The loader compares exact versions but cannot itself provide a trusted revision, root-key lifecycle, anti-rollback hardware or secure signing authority. Never allow a request, website, BLE peer or user-supplied file to select the root or trusted revision. This reference provides no user authority beyond HOLD_REVIEWABLE.

**Ed25519 verification:** This optional module uses an audited external library (`cryptography>=44,<49` in CI) rather than custom cryptography. It verifies genuine Ed25519 signatures over the existing domain-bound challenge + canonical recovery report. The keys supplied to its constructor MUST come from a separate privileged, integrity-protected reviewer registry; accepting public keys from a submitted report is never allowed. This module does not enroll identities, distribute revocations, establish trusted UTC, issue secure hardware-backed keys, or prevent rollback of reviewer policy. Passing verification only produces HOLD_REVIEWABLE, never data-release authority.

**Signed review limitation:** `assess_review_submission` delegates the signature, key trust, reviewer authority, challenge freshness and revocation check to an external trusted verifier. The Ed25519 verifier supplies actual signature checking and a local key-policy snapshot when explicitly used. The existing older tests use an insecure SHA-256 equality stand-in and MUST NOT be reused in native production. Secure source-of-trust provisioning and clock attestation remain unimplemented. The only possible success is `HOLD_REVIEWABLE`: this does not repair registers, reset checkpoints, release data or authorize imports. Native integration must implement genuine cryptographic signature verification, trusted reviewer roles and replay-resistant challenge issuance.

**Recovery evidence:** `inspect_evidence(path, anchor)` creates a deterministic JSON report with fingerprint for human review. It does not sign or publish the report, grant authorization or repair anything. The only generated decision is HOLD. Validating a checksum is NOT validating author identity. Protected signing and reviewer workflow must be built separately.

**Recovery inspection:** `inspect_checkpoint(path, anchor)` opens SQLite in read-only mode and compares its computed content root with a separately trusted anchor. It returns counts, roots and a classification; a MATCH is diagnostic only, and all other statuses remain HOLD. It deliberately exposes no repair, rollback, replay reset, import, or execution operation. Never auto-advance an anchor or rewrite receipts to force MATCH; human review and independently protected provenance are mandatory.

**Content checkpoint policy:** `ContentAnchoredReceiver` derives a domain-separated SHA-256 commitment across the complete, canonically ordered SQLite receipt set and checks it against an external trusted `(count, root)` pair. The included `FakeAnchor` exists only in unit tests. The digest is not authenticated by itself; without a separately protected anchor an attacker can rewrite both files. This variant is explicitly single-writer, and SQLite + external anchor do not share an atomic transaction: interrupted or competing writes must fail closed and require supervised recovery. It is not a working secure element, mobile keystore integration or cryptographic signature system.

**External checkpoint policy:** `AnchoredDurableReceiver` requires an OS- or hardware-protected monotonic counter implementing `read()` and irreversible compare-and-advance `advance(expected, new_value)`. The included tests use an in-memory fake counter **only**. The counter is not available in this repository. An independent secure native component must own the counter; never accept it from a website, device name, JSON payload, or untrusted file. An equal row count does NOT prove the receipt rows are unchanged. For production, require a cryptographically authenticated digest/append-only accumulator or trusted ledger anchored with the counter. No automatic reconciliation or rollback is permitted after a mismatch.

**Persistent replay security:** DurableReceiver persists only completed transfer IDs and digest metadata, never transfer payload bytes. SQLite PRIMARY KEY provides atomic replay rejection between processes using the same file, but an attacker able to delete or roll back the database can defeat its history. Keep the file under OS-managed private storage, back it with a protected monotonic ledger or hardware-backed anti-rollback mechanism for higher assurance, and do not treat this prototype as tamper-proof. The database is not migrated or automatically pruned; capacity exhaustion fails closed.

**Known limitations:** Frame headers are not authenticated. There is a local stop-and-wait ACK/retry reference but no authenticated ACK, timer implementation, BLE stack, encryption, cryptographic peer binding or live radio API. Only an immediate identical prior frame can be re-ACKed; delayed or out-of-window packets abort. The caller drives timeouts and MUST use authenticated, encrypted peer transport before relying on ACKs. The in-process buffers are not a secure secret-erasure primitive. The bridge requires an approved session and rejects sizes inconsistent with its validated offer; production integration must additionally authenticate the offer itself. Automated Python stdlib checks are configured in `.github/workflows/bluetooth-transfer-tests.yml`; check their actual GitHub Actions run status before claiming PASS.

**Status:** DRAFT / GO-13 HOLD / authorization DENY. No merge, deploy, website publishing or hardware verification is performed by this change.
