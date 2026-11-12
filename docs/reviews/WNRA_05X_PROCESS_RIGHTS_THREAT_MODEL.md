# WNRA-05X — Windows process-rights threat model and negative access matrix

**Scope:** DRAFT, native Windows test-only. **GO-13 HOLD / AUTHORIZATION DENY**.

Parent: WNRA-05W PR #325 at exact parent commit `2f4a3bf830c93fc39fc787b7c9f1bfa78d4e16bd`. Only `verification/provenance/test_windows_anchor_suspended_job_launch.py` is modified; the existing Windows workflow already watches and executes it. No production code, protocol canon, identity issuance or authority changes.

## Assets and trust boundaries

- Protected: parent launcher handles; Job Object with kill-on-close; explicitly authorized event handle; child's own process and descendants; audit evidence bound to exact commit and runner.
- Trusted for *this experiment*: the Windows CI runner and Python test controller holding original privileged handles; Windows API calls and error reporting; local test scripts.
- Not trusted as a production authority: the spawned worker, filesystem marker content as a cryptographic proof, broad inherited handles, a child-provided PID without validation, or a passing CI status alone.
- Entry points: `CreateProcessW`, `STARTUPINFOEXW` attribute list, `DuplicateHandle`, `OpenProcess`, `SetEvent`, `WaitForSingleObject`, `TerminateProcess`, `AssignProcessToJobObject` and `ResumeThread`.

## Threats, controls and residual risks

| Threat | Current local control / test | Residual risk or missing safeguard |
|---|---|---|
| Code runs before containment | `CREATE_SUSPENDED` + assign before `ResumeThread` (05T) | General race freedom, DLL initialization/remote thread injection, production launcher not proven |
| Job descendant escapes | Job membership, kill-on-close and explicit breakaway refusal (05S–05V) | Arbitrary breakaway and nested job configurations, privileged escape vectors not proven |
| Accidental or broad inheritance | `bInheritHandles=False` and narrow `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (05U–05V) | No global handle census, inheritable descriptors of other kinds, handle duplication across boundaries |
| Rights granted beyond need | `EVENT_MODIFY_STATE` only (05W), `SYNCHRONIZE` only (05X) | Only named event type; ACL/DACL audit and malicious-worker rights escalation not tested |
| Unauthorized process control | Query-only process handle cannot terminate (05W), cannot wait (05X) | Controller still retains higher-right process handles; no hardened token or broker separation |
| Child impersonation / token abuse | **NOT IMPLEMENTED** | Restricted primary token, integrity levels, privileges, AppContainer, impersonation controls require independent design |
| Resource exhaustion | 64 KiB local request cap, 96 MiB per-process Job limit, bounded test workloads (05P–05S) | Job-wide commit/CPU budgets, resource exhaustion by spawned descendants, production quotas not established |
| Forged evidence | Exact commit, named CI runs and test cases | No independent attestation, tamper-evident signed evidence, verified trust root |

## WNRA-05X negative access matrix

The new Windows-only test transfers an event handle with **only `SYNCHRONIZE`** using `DuplicateHandle` and the WNRA-05V allowlist. Inside the suspended-then-job-assigned child, `WaitForSingleObject` must return `WAIT_TIMEOUT` (the event is not signaled), `SetEvent` must fail with Win32 **5 / ACCESS_DENIED**, and the unlisted original event must be absent. This complements the existing `EVENT_MODIFY_STATE` test proving `SetEvent` succeeds but waiting is denied.

The existing query-only process-handle test is extended: `TerminateProcess` **and** `WaitForSingleObject` on the `PROCESS_QUERY_LIMITED_INFORMATION` handle must fail with Win32 5, while the trusted controller's Job close must still terminate its worker. All test workers are kept in Job Objects and reaped; they do not gain signing/issuance/production admission.

## Required evidence

Exact-head native Windows CI must show `WNRA05X_EVENT`, the expanded `WNRA05W_PROCESS` result, and 05T/U/V/W regressions. Report the real test outcome, preserve any failing attempts, and do not claim generic token isolation or full process-security certification.

**TRIAS:** GO-13 HOLD / AUTHORIZATION DENY. **ORACLE:** evidence is exact-head and runner-scoped. **MENTOR:** a future restricted-token design needs its own threat model and implementation authorization; no merge, deployment, activation, release or enrollment here.
