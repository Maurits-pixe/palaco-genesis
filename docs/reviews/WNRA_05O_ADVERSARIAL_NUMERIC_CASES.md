# WNRA-05O — adversarial numeric byte forms

**DRAFT / TEST-ONLY / GO-13 HOLD / AUTHORIZATION DENY.**

Parent: WNRA-05N DRAFT PR #316, exact base `cdfdbf2d835957f9520e41a7446c354be5570bb2`. Prior 17-case shared corpus and 14 numeric boundary fixtures remain unchanged.

A new `AdversarialNumericComparison` in `verification/provenance/test_windows_anchor_error_codes.py` constructs twenty raw JSON mutations of the `sequence` token: leading zero, negative leading zero, plus sign, trailing or leading point, double minus, digit separator, hex syntax, signed exponent, huge exponent, negative exponent, fractional half, fractional negative zero, quoted number, NaN, Infinity, 70-digit integer, Unicode fullwidth digit, missing value, and duplicated sequence key. All twenty must raise `FixtureByteRejected` in Python and a strict diagnostic exception in the separately executed Node fixture parser. **Unexpected parsing** and **unexpected authority** are both test failures, regardless of which diagnostic error label is emitted. This is a local negative corpus, not a generalized JSON conformance test.

The three pre-existing positive canonical vectors must continue to parse as local Python fixtures; Node's existing vector test must continue returning `authorization=DENY` and `independent_verification=NOT_EXECUTED`. No independent cryptographic custodian, trust root, signature, issuance or production authority exists here.

The workflow `.github/workflows/orcheastra-windows-metadata.yml` already watches and executes the modified `test_windows_anchor_error_codes.py`, so no workflow configuration change is necessary. Native Windows CI on the **new head** must confirm the new tests and existing regressions; previous-run evidence does not certify this candidate.

AI TRIAS: no new authority or protocol canon. AI ORACLE: compare exact-head Windows output and document any counterexamples. AI MENTOR: retain granular local diagnostics without expanding this flat parser to production.

**No merge, release, activation, or enrollment.**