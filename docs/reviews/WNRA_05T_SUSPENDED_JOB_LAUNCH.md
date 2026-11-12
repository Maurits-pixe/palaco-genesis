# WNRA-05T — suspended Windows process assignment before resume

**Status:** DRAFT TEST-ONLY CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05S DRAFT PR #321, exact base `5ec297b85a2d814cc2e177cbc2b5e852e5c7c743`. Earlier red Windows evidence for WNRA-05S is preserved in its original review. WNRA-05T adds a **new file**, `verification/provenance/test_windows_anchor_suspended_job_launch.py`, and wires it into the native Windows workflow.

## Narrow implementation

A Windows `CreateProcessW` call with `CREATE_SUSPENDED` and `CREATE_NO_WINDOW` creates a local Python test child with an untouched main thread. The test checks that the worker has not written its start marker, calls `AssignProcessToJobObject`, checks the marker is still absent, then calls `ResumeThread`. Only then may the worker start a descendant. The test obtains the descendant's `SYNCHRONIZE` handle, confirms both process handles are not yet signaled, closes the job configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and checks both process handles become signaled. A second test assigns a new suspended process and aborts by closing the job **without resuming**; it checks the marker never appears. Raw handles are closed in `finally`; on failure, any surviving primary process is terminated and reaped.

## Precise limitations

This is a local Windows Job Object feasibility test, **not** a general production-safe launcher. It does not implement restricted access tokens, privilege reductions, a hostile-process threat model, mitigation policies, descendant job-breakaway prevention in all process configurations, UI/kernel attack controls, API authentication, CPU-rate governance or a cryptographic trust root. It avoids **this tested worker's** pre-assignment execution by suspending its primary thread; it does not establish universal race freedom or hard security containment. No process is granted independent attestation, signing, admission or issuing rights.

**Evidence required:** exact-head native Windows CI showing `WNRA05T_SUSPENDED` and `WNRA05T_ABORT`, both tests `ok`, and preceding WNRA-05S regression still PASS. Any CI failure remains a recorded counterexample; correct on a new commit and rerun, never relabel failed evidence as PASS.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** exact-head native evidence only. **MENTOR:** propose production launcher architecture only after dedicated threat modeling; no silent deployment or release.

## First-run counterexample (preserved)

The first WNRA-05T commit `f5bc8705c8623ebddb8ca833e81397a339a076f6` triggered native Windows run `43156328335` (job `130977006426`), which **FAILED** both new tests before starting any child: the local test used `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` instead of the correctly imported `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION`, raising `NameError`. The three other workflows were successful. This is an implementation typo, not evidence about Job Object termination. The next commit corrects this spelling; it must receive fresh native Windows evidence and may not inherit a PASS from the older head.

The second candidate head `53612446d6975ca7f97d51231fb264e63cdccf93` also **FAILED** Windows run `43156465439`, job `130977449835`, before launching a worker: imported `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION` is the numeric information-class constant `9`, while the `ctypes.Structure` is named `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` in the existing fixture module. The code attempted to call the integer, raising `TypeError: 'int' object is not callable`. The subsequent revision aliases the structure explicitly as `JobLimitStructure` to prevent this confusion. The second failure is retained; only a newer exact head can prove execution.

The third candidate head `db89ca4bbd5c23a91709562470ef095c10332ec3` **FAILED** Windows run `43156606203`, job `130977898268`: abort-without-resume passed (`WNRA05T_ABORT`); the descendant test read a just-created but not-yet-populated PID file and asserted its contents were decimal, observing an empty string. This reveals a test-marker publication race, not a demonstrated process-assignment bypass. The next revision polls until a **complete decimal PID** has been written while checking the worker remains active; a fresh exact-head Windows run is mandatory.
