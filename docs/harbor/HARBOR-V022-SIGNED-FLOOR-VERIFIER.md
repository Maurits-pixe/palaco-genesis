# Harbor v0.22 — signed floor candidate verification

## Purpose

v0.21 classified independent checkpoint evidence but intentionally stopped
before trust verification. v0.22 adds a reference verifier that binds the
source identifier, complete anchor record, trust epoch, observation timestamp,
signature, freshness window, and monotone predecessor.

## Verification contract

A candidate is accepted only when all of these checks pass:

- the configured source identifier and candidate source identifier match;
- the candidate record, trust epoch, and timestamp are structurally valid;
- Ed25519 verifies a domain-separated payload containing every candidate field;
- the trust epoch meets the configured minimum and does not regress;
- the observation is not in the future and is not older than the freshness window;
- revision, sequence, signer epoch, and retired-signer state do not regress;
- the same revision cannot contain a different record;
- observation time does not move backwards.

The returned FloorVerification is evidence for the supplied policy. It is not a
governance root, authority token, admission result, execution permission, or
activation.

## Evidence boundary

The verifier still receives its key, source ID, minimum epoch, clock, and
freshness window from the caller. No key enrollment, trusted clock, external
service, anti-rollback persistence, quorum, or production deployment is
provided.

A future integration must obtain those inputs from independently governed
systems and retain the complete verification record.

## Verification cases

Tests cover:

- valid signed evidence;
- source and payload tampering;
- wrong key;
- future and stale timestamps;
- minimum and regressing trust epochs;
- floor regression and same-revision fork;
- freshness regression;
- invalid verifier policy;
- the distinction between verification evidence and authority.
