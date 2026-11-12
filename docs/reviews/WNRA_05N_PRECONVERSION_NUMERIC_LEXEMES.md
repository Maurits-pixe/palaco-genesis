# WNRA-05N — preconversion numeric lexeme regression

**Status:** DRAFT TEST CANDIDATE, NOT PROTOCOL CANON.

Parent: WNRA-05M PR #315, exact base commit `d07f0bc903e3a8d8e3185ac8304924df475a9c3b`.

In the **test-only Node flat fixture parser**, the exact decimal `sequence` token is checked using `BigInt` before `JSON.parse` can convert it to a JavaScript `Number`. This distinguishes `-0` (`NEGATIVE_ZERO`) and integers outside ±(2^53−1) (`UNSAFE_INTEGER`). Python already used these local rejection labels. Neither negative case was accepted before this change; this strengthens diagnostic specificity and prevents reasoning based on rounded numbers.

The existing 17 negative cases and WNRA-05M fourteen numeric boundary cases remain intact, while expected Node codes change only for named numeric lexemes. A direct Node test checks four negative tokens and four canonical positive values, which still return `authorization: DENY` and `independent_verification: NOT_EXECUTED`. This is **not** a general JSON wire parser, independent signer, authority, or proof of general parser equivalence.

**Required evidence:** fresh CI on the exact WNRA-05N head, especially native Windows regression; collect job log lines for `WNRA05H_CASE`, `WNRA05M_CASE`, and Node test `WNRA-05N numeric lexemes classify before Number precision loss`. Do not claim PASS before execution. Older PR heads remain preserved. No merge, release, issuance, cryptographic credential enrollment or production activation.

**TRIAS:** scope and authorization unchanged. **ORACLE:** exact Windows evidence required on new head. **MENTOR:** keep targeted diagnostic hardening; do not generalize lexeme checks into public protocol canon without separate approval.

**GO-13 HOLD / AUTHORIZATION DENY.**
