# HARBOR v0.35 — Recovery latency evidence protocol

Status: DRAFT
Last Updated: 2026-10-30

## Scope and provenance

This is an opt-in measurement protocol for the ignored `recovery_latency_characterization` test introduced in HARBOR v0.34 (PR #175). It does not alter the signed anchor format, recovery algorithm, authority rules, CI gates, or production runtime.

Parent candidate: `e6b25e45235fe974e1ed71e7c6dbb2c5da592d35` (PR #175). The benchmark source and this document must be bound to the **exact commit checked out at execution**, not merely a branch name.

## Procedure (maintainer-operated, non-production POSIX host)

1. Record repository URL, full commit SHA, relevant workflow/config SHA (if applicable), date/time in UTC, host/runner model, OS/kernel, filesystem and mount type, Rust and cargo versions, build profile, CPU load/context, cache/warm-up assumptions and test command. Do not include secrets, user data or private paths.
2. Check out the intended full commit SHA on an isolated test machine, with the Rust toolchain and dependencies installed. Verify `git rev-parse HEAD` matches that SHA.
3. Execute exactly:

   ```sh
   cargo test -p palaco-harbor --lib recovery_latency_characterization -- --ignored --nocapture
   ```

4. Save exit code and complete stdout/stderr as immutable run evidence. Expect exactly one `HARBOR_RECOVER` line per frame count 1, 16, 64, each with `runs=7`, `min_us`, `median_us`, `max_us`. A missing line is **INCOMPLETE**, not a zero.
5. Confirm test success and that each reported group satisfies `0 <= min_us <= median_us <= max_us`. The test asserts identical recovered content for all seven timings; check the test result rather than assuming timings imply integrity.
6. Repeat independently if comparing hosts or making performance conclusions; record run IDs separately. Never silently replace a failed run with a later successful run.

## Report contract

Use an append-only record per executed run:

| Field | Required meaning |
| --- | --- |
| `repository`, `commit_sha`, `test_source_sha` | Exact source binding; `test_source_sha` can be the Git blob SHA |
| `runner`, `os_kernel`, `filesystem`, `toolchain`, `profile` | Reproduction context, with `UNKNOWN` when not captured |
| `timestamp_utc`, `command`, `exit_code`, `run_id` | Execution identity and outcome |
| `frames_1`, `frames_16`, `frames_64` | Each has `runs=7`, `min_us`, `median_us`, `max_us` |
| `raw_log_reference`, `raw_log_digest` | Raw evidence locator and computed digest; never fabricate |
| `interpretation`, `limitations`, `reviewer` | Human review and caveats, distinct from measurements |

Use `NOT EXECUTED` for unrun samples, `INCOMPLETE` for missing/invalid evidence, `FAIL` for an executed failing test, and `OBSERVED` for a complete passing measurement. `OBSERVED` is **not** a release, integrity or performance-threshold PASS.

## Boundaries and reviewer checklist

- Measurements are host-local, cache-sensitive and not comparable without environment disclosure.
- Setup and append operations are outside measured `recover(None)` timing.
- `Instant` and microsecond integer conversion may report zero for sufficiently fast runs; zero is not proof of no work.
- The test uses a temporary local POSIX directory; it does not prove power-loss durability, remote federation behaviour or concurrent hostile filesystem resistance.
- SHA-256 frame fingerprinting and in-flight rereads do not detect an ABA modification restored before reread, and signed frames cannot independently detect full snapshot rollback without a governed external high-water checkpoint.
- TRIAS: verify no change to admission, authority or release gates. ORACLE: verify exact-head execution, environment metadata, raw logs and missing evidence. MENTOR: make performance conclusions only when repeatability and workload relevance are demonstrated.

## Transition

`DRAFT PROTOCOL` → `BENCHMARK EXECUTED / EVIDENCE CAPTURED` only after a real maintainer run with the full report. Then human review may evaluate the observation. **Merge, deployment, production authorization and release remain HOLD** pending separate applicable gates.
