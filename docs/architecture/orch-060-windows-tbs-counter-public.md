# ORCH-060 — Windows TBS NV counter public reader

DERIVED implementation on ORCH-059 for the user's Windows PC with TPM. Adds a concrete C# P/Invoke adapter for Windows TPM Base Services, a PowerShell entry point, and binary parser tests in both Windows shells. The only command builder exposed is TPM2_NV_ReadPublic (0x169); native submit methods are private. It does not define, increment, undefine or clear a counter, create keys, read the counter value or change policy. The caller supplies an existing NV index and an independently retained SHA-256 NV Name; no index scanning or inferred provisioning.

The reader opens a TPM 2.0 TBS context (version 2, includeTpm20 bit), submits at locality 0/normal priority, caps response storage to 4096 bytes and closes the context in finally. It fails on TBS/TPM errors. Native calls have no application-level timeout in this slice; no liveness guarantee is made.

Parser checks exact outer size/no trailing bytes, no-session response tag, success code, NV public size, SHA-256 name algorithm, exact requested index, 0/32-byte authorization policy, eight-byte counter type and exact Name length. It recomputes Name from the complete public area and compares both returned and independently supplied Name. Short/truncated frames, mismatches and other algorithms/types fail closed.

Tests compile the real native adapter on Windows, validate fixed command bytes, every truncated prefix, mutated frame fields, wrong pin/index, oversized data, non-counter type/eight-byte layout even under recomputed matching names, and both supported authPolicy layouts. Valid input hardware calls are NOT EXECUTED; malformed input is tested before the native boundary. CI does not prove TBS access or the state of the user's TPM.

Run only after an independently governed counter/index/Name has been provisioned. The fixture index in tests is NOT a provisioning recommendation. Keep Get-PalacoTpmCounterPublic.ps1 and PalacoTpmCounterPublic.cs together, then supply -NvIndex and -ExpectedNvName. Do not copy an observed Name back as its own trust evidence.

A matching Name establishes public-area consistency, not a signed attestation, current counter value, TPM identity, reset/clear resistance, authorization lifecycle or atomic digest/counter pin storage. Mutable TPM attributes can affect Name; a future implementation must define lifecycle and pin refresh policy explicitly. AntiRollbackVerified and RuntimeAuthorized always remain false. This is not yet a PolicyPinBackend implementation.

AI-review through three lenses: TRIAS — read-only hardware boundary cannot provision or activate; ORACLE — binary validation and Name hashing are testable but real hardware and reset/restart security remain unverified; MENTOR — narrow native surface and explicit independent index/Name prevent accidental arbitrary TPM writes. Dissent: production anti-rollback remains HOLD until provisioning, authenticated counter reads, update protocol and target-device tests exist.

Primary references: Microsoft TBS_CONTEXT_PARAMS2 https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tbs_context_params2 ; Tbsip_Submit_Command https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command ; Microsoft TPM reference https://github.com/microsoft/ms-tpm-20-ref ; TCG TPM 2.0 Part 2 https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Version-184_pub.pdf .

Next transition: design/provision a governed Windows NV counter and its independent identity, then implement authenticated counter-value observation and crash-safe digest/counter adoption. Actual target-device readiness report is still missing. Independent review and GO-13 remain required for merge/activation. Exact-head CI evidence is in the PR.
