# WNRA-05U — Windows handle custody and descendant Job Object membership

**Status:** DRAFT TEST CANDIDATE / GO-13 HOLD / AUTHORIZATION DENY.

Parent WNRA-05T DRAFT PR #322 at exact commit `0da38461ad58ae55dcf0c08d185fcdf251df1e17`. This revision changes only the existing Windows-native test file, which is already watched and executed by `.github/workflows/orcheastra-windows-metadata.yml`. Production runtime and protocol code are unchanged.

## New assertions

1. In the existing suspended worker + descendant scenario, use `IsProcessInJob` to confirm both the parent and the live descendant are **members of the particular configured Job Object before closure**. This is stronger than inferring containment from termination alone. The descendant is opened with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`; the parent handle comes from the suspended `CreateProcessW` result.
2. Create a Windows event in the test parent and explicitly set `HANDLE_FLAG_INHERIT`. Launch a suspended Python test worker via the existing `CreateProcessW` wrapper that passes `bInheritHandles=False`; assign to the Job Object before resuming. Inside the child, `GetHandleInformation` is used to verify that the numeric parent event handle was **not inherited**. On success the test logs `WNRA05U_HANDLE ... child_inherited=false authorization=DENY`.
3. Keep both the ordinary WNRA-05T termination path and abort-without-resume path; ensure the parent event, Job Object, thread and process handles are closed in `finally`, including on failure. Membership emits `WNRA05U_MEMBERSHIP ... authorization=DENY`.

## Strict limitations

The event-handle test checks only one explicitly inheritable fixture handle, not arbitrary handle types, duplicate-handle attacks, privileged process tokens, secure access control lists, creation-time policies or intentional handle passing. `bInheritHandles=False` is an API call flag, not a substitute for a complete Windows threat model. Job Object membership and kill-on-close do not establish general breakaway resistance, container isolation or production security. No resource quota, authorization, issuance, real anchor or trust root is added.

**Required evidence:** new head native Windows CI with both `WNRA05U_MEMBERSHIP` and `WNRA05U_HANDLE` log lines, the three WNRA-05T tests `ok`, and prior regressions passing. No verified PASS before exact-head logs. Preserve failures as historical evidence; do not silently relax expectations.

**TRIAS:** No authorization. **ORACLE:** Evidence remains SHA- and runner-bound. **MENTOR:** Review future handle allowlisting and breakaway/privilege policies separately; do not imply secure production launcher.
