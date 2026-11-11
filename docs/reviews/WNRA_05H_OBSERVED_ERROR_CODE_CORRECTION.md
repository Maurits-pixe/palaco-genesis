# WNRA-05H — observed correction to the WNRA-05G derived code matrix

This is an **append-only review correction**. It does not rewrite the earlier WNRA-05G document or declare canonical diagnostic semantics.

## First executable evidence

- Exact failing candidate head: `1cd78bf7ef5454018c1b586ef424b03b8adaf10e`.
- GitHub Actions SBOM Evidence Candidate run `43003536443`, job `130465251078`, generator test step: **FAIL (2 expected-code assertions)**.
- All 17 shared inputs were still rejected. The test exposed two inaccurate **DERIVED** Node labels from WNRA-05G:

| Case ID | WNRA-05G derived Node label | Actually observed Node label | Python observed |
| --- | --- | --- | --- |
| `negative-zero` | `NONCANONICAL_TEST_BYTES` | `INVALID_SEQUENCE` | `NEGATIVE_ZERO` |
| `utf8-bom` | `UTF8_BOM` | `NONCANONICAL_TEST_BYTES` | `UTF8_BOM` |

Both are DENY. Root-cause hypotheses from code inspection:
- Node parses `-0` as JavaScript negative zero and rejects because `sequence <= 0`, before a canonical-byte comparison.
- The JavaScript `TextDecoder` default BOM handling strips the leading UTF-8 BOM. Therefore the later `startsWith('\\ufeff')` check does not see it; canonical-byte comparison rejects it.

These hypotheses are source analysis, not independent security certification.

## Corrected expected comparison

The WNRA-05H executable test now pins these two **observed** Node codes. The corrected matrix has **7 matching and 10 differing labels**, rather than the earlier 8/9 static estimate. The fail-closed behavior, not error-label equality, is the maintained invariant.

## Remaining limits

- The new WNRA-05H head must pass fresh native Windows and general CI; previous run cannot certify the corrected head.
- This test uses one Python coordinator to query a separate Node parser; it does not create an independent authority or cryptographic custodian.
- No wire protocol version is approved. No release, merge, issuance, or runtime authority is granted.

**GO-13 HOLD / AUTHORIZATION DENY**.
