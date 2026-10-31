# Harbor v0.25 — key-bound floor signature envelope

## Purpose

The v0.23 governed-floor bridge checks the expected key identifier against
policy and a KeyRegistry, while the v0.22 source signature binds the complete
floor candidate. v0.25 adds an optional second signature over both:

1. the exact external key identifier; and
2. the complete v0.22 signed floor payload.

This closes the ambiguity where two registry labels could refer to the same
public key without the label itself being covered by the signature.

## Contract

KeyBoundGovernedFloorCandidate contains:

- key_id;
- the existing SignedFloorCandidate;
- key_binding_signature.

The verifier first pins one registry record, runs the complete v0.23 governed
checks against that pinned record, then verifies the additional signature over
the domain-separated key-bound bytes.

A registry lookup that is missing, unavailable or uncertain fails closed. A
changed key label, changed floor payload, wrong binding signature, stale key,
clock rollback, revocation, floor regression or freshness regression cannot
produce evidence.

## Compatibility and boundary

The v0.22/v0.23 evidence contract remains available. The key-bound envelope is
an additive stronger option and does not silently change old signatures.

The envelope still does not:

- enroll or authorize keys;
- establish a source-to-key governance mapping;
- provide a trusted clock;
- persist an anti-rollback floor;
- provide quorum or an external checkpoint service;
- grant admission, execution, publication, release, merge or activation.

A successful result remains verification evidence only.

## v0.26 hardening slice

The follow-up hardening keeps the envelope draft-only and adds explicit
boundary evidence:

- malformed key identifiers are rejected before registry access;
- the registry is resolved exactly once and the returned record is pinned for
  both the governed and key-bound checks;
- the key-bound domain is tested as distinct from the inner floor-signature
  domain.

These checks reduce lookup ambiguity and prevent an invalid identifier from
being treated as an authority lookup request. They still do not replace an
independent human security review.

## Tests

The reference tests cover:

- valid key-bound evidence;
- cryptographic binding of the key label;
- payload tampering;
- binding-signature tampering;
- registry outage and unknown key;
- evidence versus authority.
