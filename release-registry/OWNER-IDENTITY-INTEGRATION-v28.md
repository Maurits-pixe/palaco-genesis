# PALACO Trusted Evidence v28 — Owner Identity Integration

**DRAFT / GO-13 HOLD.** This is an authenticated-session **verification contract** for the v27 owner decision gateway, **NOT** a connection to a running PALACO One identity service. No accounts, signing keys, login endpoints or real sessions are issued or modified.

## Implementation

`owner_identity_integration_v28.py` exports `OwnerIdentityAdapter(issuer, audience, pinned_public_keys, trust_key, check_current_owner, trusted_now)`, which implements the existing v27 callback `verify_session(assertion, "OWNER_REVIEW", day)`.

- The input is canonical JSON containing exactly `claims`, `key_id`, and `signature_b64`. Ed25519 validates the domain-separated `PALACO-OWNER-SESSION-ATTESTATION-v28` signed claim bytes against an **independently provisioned and pinned** 32-byte public key. Public keys delivered in an untrusted token are never accepted.
- Claims are strictly schema-checked: issuer, audience, subject, session identifier, device identifier, issue/not-before/expiry/MFA timestamps, `phishing-resistant-mfa` method, `OWNER_REVIEW` action scope, and the exact role set `["OWNER"]`. This is deliberately narrow; roles are not unioned or inherited.
- Validity requires a fresh trusted UTC epoch time, a session lifetime of **at most 600 seconds**, and MFA no older than **300 seconds**. Time outside the permitted bounds, expired or not-yet-valid assertions and non-integer timestamps all fail closed.
- A valid signature alone is never sufficient. The required external `trust_key(key_id, claims)` must check current issuer-key enrollment, revocation and scope, while `check_current_owner(subject, session_id, device_id, action, day)` must independently verify current active OWNER role, session/device revocation, the owner's access scope and current permission. **Only literal Boolean True** from both callbacks is accepted.
- The adapter returns an authenticated owner identifier when every requirement is met, otherwise `None`. The v27 gateway treats `None` as `SESSION_NOT_AUTHORIZED`; session validity is checked again on final confirmation.
- This adapter **does not** sign tokens, store secrets, grant account rights, implement an OAuth/OIDC flow, or connect to PALACO One/Supabase. Those services and the independent trust callbacks are not present in this development candidate.

## Synthetic tests

```sh
python -m unittest discover -s release-registry -p 'test_owner_identity_integration_v28.py' -v
```

28 synthetic regression cases have been authored and committed: valid ephemeral-key Ed25519 session, wrong signature/issuer/audience/scope, missing or extra roles, MFA mode and age, expiry and not-before, overlong session, revoked key and owner, truthy non-Boolean callbacks, unknown key, noncanonical/extra/missing fields, unavailable trusted clock/revocation, malformed trust store, and full v27 begin/confirm including owner revocation between stages.

**The tests have been committed but not independently verified as executed.** Synthetic verifiers that always return True MUST NOT be reused for live access.

## Remaining critical gates

1. Independently authenticated **real PALACO One** owner-role source with role/version binding, current revocation checks, session validation, device enrollment, phishing-resistant MFA and a secure session issuer/key-management architecture.
2. Secure current-time provider, qualified UTC vs Europe/Amsterdam daily calendar policy, network transport authentication, session confidentiality, CSRF protection, rate limiting and session-origin/device proof-of-possession controls. A signed bearer assertion alone can still be stolen and replayed while valid.
3. Formal identity/authorization review, including how the initial FOUNDING_OWNER role is independently verified and how privilege/revocation is changed or contested.
4. No proof that independent role/revocation callback results and the v25 SQLite review commit are atomic together; a last-moment race remains. Independent anti-rollback audit and fault-injection/concurrency tests are still required.
5. No live website or backend endpoint has been deployed, no login/account is modified, and the read-only v26 JA/NEE HTML buttons remain disabled until a secure authenticated backend exists.

**A JA review remains an acknowledgment only; it NEVER authorizes v24 recovery, publishing, release, identity issuance or account modification. GO-13 HOLD.**
