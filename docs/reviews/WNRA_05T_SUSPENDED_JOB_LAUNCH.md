# WNRA-05T — suspended Windows process assignment before resume

**Status:** DRAFT TEST-ONLY CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05S DRAFT PR #321, exact base `5ec297b85a2d814cc2e177cbc2b5e852e5c7c743`. Earlier red Windows evidence for WNRA-05S is preserved in its original review. WNRA-05T adds a **new file**, `verification/provenance/test_windows_anchor_suspended_job_launch.py`, and wires it into the native Windows workflow.

## Narrow implementation

A Windows `CreateProcessW` call with `CREATE_SUSPENDED` and `CREATE_NO_WINDOW` creates a local Python test child with an untouched main thread. The test checks that the worker has not written its start marker, calls `AssignProcessToJobObject`, checks the marker is still absent, then calls `ResumeThread`. Only then may the worker start a descendant. The test obtains the descendant's `SYNCHRONIZE` handle, confirms both process handles are not yet signaled, closes the job configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and checks both process handles become signaled. A second test assigns a new suspended process and aborts by closing the job **without resuming**; it checks the marker never appears. Raw handles are closed in `finally`; on failure, any surviving primary process is terminated and reaped.

## Precise limitations

This is a local Windows Job Object feasibility test, **not** a general production-safe launcher. It does not implement restricted access tokens, privilege reductions, a hostile-process threat model, mitigation policies, descendant job-breakaway prevention in all process configurations, UI/kernel attack controls, API authentication, CPU-rate governance or a cryptographic trust root. It avoids **this tested worker's** pre-assignment execution by suspending its primary thread; it does not establish universal race freedom or hard security containment. No process is granted independent attestation, signing, admission or issuing rights.

**Evidence required:** exact-head native Windows CI showing `WNRA05T_SUSPENDED` and `WNRA05T_ABORT`, both tests `ok`, and preceding WNRA-05S regression still PASS. Any CI failure remains a recorded counterexample; correct on a new commit and rerun, never relabel failed evidence as PASS.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** exact-head native evidence only. **MENTOR:** propose production launcher architecture only after dedicated threat modeling; no silent deployment or release.
