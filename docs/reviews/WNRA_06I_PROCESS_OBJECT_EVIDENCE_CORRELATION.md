# WNRA-06I — process/object access correlation, no causal loader attribution

**DRAFT TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent WNRA-06H DRAFT PR #336 exact SHA `1cf11670c54011f8911382d062555e9c6993a10d`.

## Purpose and evidence contract

The earlier WNRA-06H process-bound experiment verified PID, image path, actual worker token, Job Object membership and exit state. WNRA-06F separately verified actual read/execute file-open decisions under restricted-token impersonation. These two evidence streams are **related but independent**: the controller's direct file open is not the worker's Windows loader operation.

The new native Windows test `verification/provenance/test_windows_anchor_process_object_correlation.py` executes the same Python sleep worker with three Low-integrity token policies (low-only, current-user restricting SID, BUILTIN\\Users restricting SID). The low-only worker must remain alive; the restricted outcomes are observed as created-and-live, post-resume-blocked or create-blocked. For each restricted-SID variant it then creates an equivalent reduced token and performs independent read and execute `CreateFileW` opens on the **same Python executable**, under temporary restricted-token impersonation with immediate `RevertToSelf`. These separate observations are linked by policy variant and the tested image name, *not* by a fabricated process-call trace.

Required markers:
- Two `WNRA06I_CORRELATION variant=...` rows with `control=worker_live`, worker outcome, read and execute open success/error, `loader_access_traced=false`, `cause_attributed=false`, `authorization=DENY`.
- `WNRA06I_SUMMARY` with both restricted outcomes, `evidence_scope=process_plus_separate_object_opens` and `root_cause=UNKNOWN`.
- Prior WNRA-06F/G/H regression tests remain required on the same exact-head Windows workflow.

## Interpretation and limits

The comparison can reveal that process execution is blocked despite a separate open succeeding, or that file permissions deny the tested open. **Neither finding identifies the actual failed loader operation**, its stack, object path, security descriptor, kernel callback, file mapping, directory traversal, process parameters, or a source-specific Win32 API call. No file path may be named as causal absent independent loader- or process-specific telemetry.

No ACL changes, audit/SACL changes, tracing drivers, token privilege escalation, network policy, production launcher, issuance or authorization. All Job Object, process/thread and token handles are cleaned up on both success and failure.

**TRIAS:** HOLD / DENY. **ORACLE:** exact head/run/job + three markers. **MENTOR:** process-specific access tracing requires separate reviewed instrumentation and a causal evidence chain. PR remains DRAFT, with no merge/release/activation.
