# ED25519-A2-APPROVALS-0.1 — candidate

Status: DRAFT, not a production trust policy. Current governance intent is `release-policy-v0.3.json`: two designated interim reviewers, Maurits and the second reviewer recorded there; Ambassadors later through explicit transfer. Both production key bindings and the second reviewer's identity, distinctness and acceptance remain open. An implementation test must never be counted as either person's approval. Governance-intent v0.3 is not an executable policy: the executable profile below retains version 0.2 and requires independently pinned trust configuration. Threshold-one compatibility does not authorize use of one reviewer under the current governance decision.

## Independently trusted inputs

The caller supplies the expected policy digest, descriptor digest, source commit, last accepted release sequence and previous approved-release digest separately from the received files. Missing anchors fail INCOMPLETE. Wrong anchors fail CONFLICT. A policy bundled with its own purported trusted digest is not sufficient. Do not accept user-controlled anchors on a public endpoint.

The executable policy has exactly: `policy_version: "0.2"`, `signature_profile: "ED25519-A2-APPROVALS-0.1"`, `governance_phase: "INTERIM"`, `required_distinct_reviewers` (integer 1 or 2), `citadel_id`, `world_id`, `reviewers`. Each reviewer entry has exactly `reviewer_id`, `key_id`, `public_key_hex` (32 raw Ed25519 bytes as lowercase hex), and `status` (`ACTIVE` or `REVOKED`). The number of entries equals the threshold. Reviewer IDs, key IDs and public keys must each be unique. These are identifiers of externally established identity/key bindings, not identities proved by the tool.

The digest is SHA-256 of `PALACO:CITADEL:RELEASE-POLICY:A2` + NUL + PALACO-JSON-A1 canonical policy bytes. Adding/removing a reviewer, changing the threshold, revoking or rotating a key changes the policy digest and requires distribution of a newly trusted anchor. An old policy's signatures cannot establish the current policy's validity. This prevents substitution only if the caller uses the current authenticated anchor; stale policy trust can hide revocation.

## Signed approval envelope

Exact fields: `signature_profile`, `policy_digest`, `descriptor_digest`, `source_commit`, `citadel_id`, `world_id`, `release_sequence`, `previous_release_digest`, `approvals`. Approvals are sorted by ASCII reviewer ID, one per required reviewer, with exactly `reviewer_id`, `key_id`, `signature_hex` (64 raw signature bytes as lowercase hex). Unknown fields and malformed values fail closed.

Each reviewer signs:

```
UTF8("PALACO:CITADEL:RELEASE-APPROVAL:A2") || 0x00 ||
canonical(envelope minus approvals, plus reviewer_id and key_id)
```

This uses plain Ed25519 over the specified message, not Ed25519ph. Signature bytes are outside the signed statement; all policy, descriptor, resource, commit and chain context is inside. The verifier never obtains a public key from the approval envelope and never replaces the trusted policy with claimed metadata.

After successful verification, the continuity digest is SHA-256 of `PALACO:CITADEL:APPROVED-RELEASE:A2` + NUL + canonical full envelope including ordered approvals. The existing unsigned descriptor and original A1 reference vectors are unchanged.

## Replay, revocation and handover

Initial trusted state is sequence 0 and previous digest null. The next accepted envelope must have sequence exactly last+1 and the exact previous approved-release digest. Sequence <= last is replay/rollback; a future gap is INCOMPLETE; a different previous digest is CONFLICT. Every signature must verify against an ACTIVE designated key. Duplicate identities, duplicate key material, revoked keys, signatures copied between reviewers and silently changed contexts are rejected.

This offline verifier does not persist state. A production caller must atomically compare and advance the continuity anchor after accepting an envelope. Reusing stale state allows repeated verification of the same release; concurrent acceptance and durable anti-rollback enforcement remain integration gates. No PostgreSQL implementation is introduced here.

Ambassador governance is deliberately UNKNOWN in this profile. Handover needs a new approved policy/profile, identity bindings and effective release boundary. Do not enable it by changing a display name. Current-world authorization and Citadel lifecycle activation remain separate.

## Result and execution boundary

Success: `result: VALID`, `scope: A2_SIGNATURES_AND_ARTIFACT_INTEGRITY`, `production_release: false`, plus the continuity `release_digest`. It means the signatures match the externally pinned policy and the original artifact checks pass. It does not establish source truth, trusted Git ancestry, human identity without an authenticated key binding, current constitutional authority or deployment permission. Non-VALID results exit nonzero; the CLI's zero exit represents only this narrow check. The older unsigned-candidate CLI continues to exit nonzero even for intact artifacts.

Use an offline artifact snapshot. No network access, private-key reading, signing, tagging, merging or deployment is performed by the verifier. `test_approvals.py` generates ephemeral synthetic keys and exercises both threshold choices and adversarial cases. No test public key should enter the real trust policy.

```sh
python3 -m pip install -r tools/citadel_a2/requirements.txt
python3 tools/citadel_a2/test_approvals.py
```

Before production use: verify both designated reviewers' distinct identities and real public keys through an independent channel, approve/freeze this candidate, establish authenticated policy distribution and revocation/rotation, provide durable continuity storage, and obtain explicit release authorization.
