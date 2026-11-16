# WNRA-06O — native Windows command-processor entry markers

**DRAFT TEST ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Stacked on WNRA-06N DRAFT PR #342, exact parent SHA `1a4979170549dcb91908f0e07093b120b21c401c`.

## Scope

WNRA-06N observed that Python `os._exit(37)` and `os._exit(53)` markers were both reached under a Low-integrity nonrestricting-SID token, but neither marker was reached under current-user or BUILTIN\\Users restricting SID tokens; the latter exited `0xC0000022`. That experiment did not distinguish failures during Python initialization from a broader Windows process execution failure.

WNRA-06O adds `verification/provenance/test_windows_anchor_cmd_entry_markers.py`. It reuses the verified suspended-create/job-before-resume/token/PID/image fixture, but launches the Windows-native `System32\\cmd.exe` image rather than Python, with two independent `/d /c exit /b 37` and `/d /c exit /b 53` marker commands. `cmd.exe` executes its own built-in `exit` command: no Python interpreter, script file, output redirection, pipes or external commands are involved.

Each of the three Low Integrity token variants (nonrestricting `low_only`, current-user restricting SID, BUILTIN\\Users restricting SID) receives both marker tests, yielding six `WNRA06O_CMD` and one `WNRA06O_SUMMARY` diagnostic records. Both low-only marker exits are **required** for test success. Restricted outcomes are recorded, not predetermined. Child identity, token integrity and restricted flags, job object custody, no inherited handles, a 3-second bounded wait and cleanup remain enforced. Existing WNRA-06N Python marker regressions remain mandatory.

## What this cannot establish

A matching cmd marker confirms its command processor reached the built-in `exit` instruction; it is not a loader call trace. A nonmatching marker, including `STATUS_ACCESS_DENIED`, does not identify an access-denied file, DLL, directory, ACL ACE or specific Windows initialization step. If both images fail only with restricting SIDs, that is evidence against a uniquely Python-script-specific explanation, **not conclusive proof of which shared Windows loader mechanism failed**. The root cause remains UNKNOWN absent independently captured process-specific events.

No ACL, SACL, audit-policy, driver, token privilege grant, production admission, merge, release, signing, issuance or activation changes.

**TRIAS:** GO-13 HOLD / DENY. **ORACLE:** exact commit/run/job evidence. **MENTOR:** strengthen fault localization without weakening security policy.
