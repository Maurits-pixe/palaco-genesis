# Harbor v0.23 — governed signed-floor bridge

## Purpose

v0.22 verified a signed floor candidate against caller-supplied source, key,
time and freshness policy. v0.23 composes that verifier with the existing
KeyRegistry contract and makes the source/key pair, key lifecycle, registry
epoch and monotone trusted-time snapshot explicit in one fail-closed call.

## Contract

The bridge accepts a candidate only when:

- the policy source identifier and candidate source identifier match;
- the policy key identifier and candidate key identifier match;
- the registry returns exactly that key;
- the key is not revoked and its validity interval is structurally valid;
- current trusted time is not below the accepted high-water mark;
- current and observation time fall inside the key validity window;
- the registry key epoch and candidate trust epoch meet the configured floors;
- the Ed25519 signature covers the complete v0.22 candidate;
- freshness, predecessor monotonicity, same-revision conflict and revocation
  monotonicity pass through the v0.22 verifier;
- a prior registry epoch cannot be replaced by an older one.

Registry outage, uncertain registry response, malformed record, revoked key,
clock rollback and all verification failures hold closed. No local fallback is
allowed.

## Evidence boundary

GovernedFloorVerification is evidence only. It is not a trust root, admission
result, authorization grant, execution permission, publication result, release,
merge or activation. The bridge does not enroll keys, persist a trust floor,
supply a trusted clock, provide a network service, or establish a source/key
mapping beyond the explicit caller policy.

The production gate still requires independently authenticated registry state,
durable monotone time and floor storage, key-rotation/revocation governance,
crash recovery, and human security review.

## Tests

The reference tests cover:

- valid registry-bound signature and source/key binding;
- unknown, unavailable and uncertain registry outcomes;
- revocation and time rollback;
- key validity boundaries;
- trust-epoch floor;
- predecessor registry and floor monotonicity;
- evidence-versus-authority separation.
