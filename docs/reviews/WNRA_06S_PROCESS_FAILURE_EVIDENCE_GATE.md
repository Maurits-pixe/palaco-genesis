# WNRA-06S — process-specific failure evidence review gate

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY**

Parent WNRA-06R PR #346 exact SHA `4dd5f50d5e65985474ba0cf1a71349140e7661b2`.

## Evidence policy

WNRA-06H through WNRA-06R established process and primary-thread exit status `0xC0000022`, unavailability of restricted process Toolhelp snapshots, separate controller file-open results, PE imports and bounded polling. None of these indirect facts alone identifies a failed Windows loader object. WNRA-06S implements an independent fail-closed **candidate-for-review filter**, without creating a new loader event source.

The pure deterministic module `verification/provenance/windows_anchor_failure_evidence_gate.py` defines an expected worker context (positive PID, nonblank image, bounded chronological lifetime, exact `0xC0000022` exit, child token verified, Job before resume) and claimed process-specific failure event (matching PID and image, event timestamp in worker lifetime, recognized provider and operation, nonblank object identity, matching `0xC0000022` status, event ID and source-record ID, and externally asserted verification). Only if these *claimed* fields align does `candidate_for_review=true`. **Regardless of this value**, `authorization=DENY` and `root_cause=UNKNOWN` are immutable.

Recognized provider labels are `kernel_file_event` and `security_audit_event`; this gate **does not collect, enable, or authenticate** either provider. Labels are untrusted strings. The `externally_verified` flag is **self-asserted** on the caller's object: it is not a signature, source-chain verification, or proof of provenance. Even a syntactically eligible forged record is only a review candidate, never causal certification. A later collector must independently establish source authenticity, kernel-to-worker PID binding, and reproducible correlation before any root-cause attribution.

The companion `test_windows_anchor_failure_evidence_gate.py` checks six categories of legacy evidence rejected as insufficient, eleven mutated or unverified event scenarios, six invalid worker contexts and one syntactically eligible **in-memory** claim which still always returns DENY and UNKNOWN. No synthetic input is described as a real captured Windows failure.

Native Windows CI requires the gate tests on the same commit while prior actual-process tests stay unchanged.

## Boundaries / TRIAS

No security ACL or SACL changes, audit policy change, driver, ETW capture, privilege escalation, production admission, signing, enrollment, merge, release or authorization.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY.

**ORACLE:** exact SHA + CI run/job and evidence-rule test log. Existing Windows access-denied `0xC0000022` remains observed, but real process-specific denial event still **NOT CAPTURED**.

**MENTOR:** next step should assess a separately approved, least-privilege collector with an independent provenance verifier; do not reinterpret static data or self-reported event labels as a confirmed loader cause.
