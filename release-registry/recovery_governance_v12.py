"""PALACO Recovery Governance v12: deterministic review/audit candidate.

This module records UNTRUSTED review metadata. An independently configured
identity/role verifier is required to assess any review. Even an accepted
review report NEVER authorizes a restore or releases production policy.
"""
import hashlib
import json
import re

from offline_stage import _canonical
from secure_policy_recovery_v11 import approval_bytes, RestoreError

SCHEMA = "palaco-recovery-governance/v12"
GENESIS = hashlib.sha256(b"PALACO-RECOVERY-GOVERNANCE-v12:GENESIS").hexdigest()
DOMAIN = b"PALACO-RECOVERY-GOVERNANCE-v12:REVIEW\x00"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
ROLES = frozenset(("owner", "independent-reviewer"))
VERDICTS = frozenset(("approve-candidate", "reject"))
MAX_REVIEWS = 64


class GovernanceError(ValueError):
    pass


def proposal(data, *, destination_name, sequence, head, evidence_sha256):
    """Bind review to exact v11 recovery approval bytes and evidence digest."""
    if type(data) is not bytes or type(sequence) is not int or sequence < 1:
        raise GovernanceError("INVALID_PROPOSAL")
    if type(head) is not str or not HEX.fullmatch(head):
        raise GovernanceError("INVALID_HEAD")
    if type(evidence_sha256) is not str or not HEX.fullmatch(evidence_sha256):
        raise GovernanceError("INVALID_EVIDENCE")
    try:
        statement = approval_bytes(
            data=data, destination_name=destination_name, sequence=sequence, head=head)
    except (RestoreError, ValueError, TypeError) as exc:
        raise GovernanceError("INVALID_DESTINATION") from exc
    return {"schema": SCHEMA, "proposal_sha256": hashlib.sha256(statement).hexdigest(),
            "evidence_sha256": evidence_sha256, "destination_name": destination_name,
            "sequence": sequence, "head": head}


def review_digest(review):
    return hashlib.sha256(DOMAIN + _canonical(review)).hexdigest()


def _validate(review, *, number, previous, plan):
    if type(review) is not dict or set(review) != {
        "schema", "index", "previous", "proposal_sha256", "evidence_sha256",
        "actor_id", "role", "verdict", "receipt"
    } or review["schema"] != SCHEMA:
        raise GovernanceError("INVALID_REVIEW")
    if (type(review["index"]) is not int or review["index"] != number or
            type(review["previous"]) is not str or review["previous"] != previous):
        raise GovernanceError("BROKEN_REVIEW_CHAIN")
    for field in ("proposal_sha256", "evidence_sha256"):
        if type(review[field]) is not str or not HEX.fullmatch(review[field]) or (
                review[field] != plan[field]):
            raise GovernanceError("PROPOSAL_OR_EVIDENCE_MISMATCH")
    if (type(review["actor_id"]) is not str or not ID.fullmatch(review["actor_id"]) or
            type(review["role"]) is not str or review["role"] not in ROLES or
            type(review["verdict"]) is not str or review["verdict"] not in VERDICTS or
            type(review["receipt"]) is not str or not 1 <= len(review["receipt"]) <= 4096):
        raise GovernanceError("INVALID_REVIEW_IDENTITY")


def replay_reviews(reviews, *, plan):
    if type(reviews) not in (tuple, list) or not 0 <= len(reviews) <= MAX_REVIEWS:
        raise GovernanceError("INVALID_HISTORY")
    if type(plan) is not dict or set(plan) != {
        "schema", "proposal_sha256", "evidence_sha256",
        "destination_name", "sequence", "head"
    } or plan["schema"] != SCHEMA:
        raise GovernanceError("INVALID_PROPOSAL")
    head, seen = GENESIS, set()
    for index, review in enumerate(reviews, 1):
        _validate(review, number=index, previous=head, plan=plan)
        if review["actor_id"] in seen:
            raise GovernanceError("DUPLICATE_REVIEWER")
        seen.add(review["actor_id"])
        head = review_digest(review)
    return head


def record_review(history, *, plan, expected_head, actor_id, role,
                  verdict, receipt):
    """Return a candidate frozen event; no external identity is asserted."""
    head = replay_reviews(history, plan=plan)
    if type(expected_head) is not str or expected_head != head:
        raise GovernanceError("STALE_REVIEW_HEAD")
    if len(history) >= MAX_REVIEWS:
        raise GovernanceError("REVIEW_LIMIT")
    event = {"schema": SCHEMA, "index": len(history) + 1, "previous": head,
             "proposal_sha256": plan["proposal_sha256"],
             "evidence_sha256": plan["evidence_sha256"],
             "actor_id": actor_id, "role": role, "verdict": verdict,
             "receipt": receipt}
    _validate(event, number=len(history) + 1, previous=head, plan=plan)
    if any(old["actor_id"] == actor_id for old in history):
        raise GovernanceError("DUPLICATE_REVIEWER")
    frozen = json.loads(_canonical(event))
    return frozen, review_digest(frozen)


def inspect_governance(reviews, *, plan, verify_role=None,
                       get_trusted_audit_anchor=None):
    """Require independent role receipts and externally pinned audit head.

    No positive decision from this function grants authorization. A distinct
    production approval process is necessary before v11 could be invoked.
    """
    head = replay_reviews(reviews, plan=plan)
    if not reviews or not callable(verify_role) or not callable(get_trusted_audit_anchor):
        raise GovernanceError("EXTERNAL_TRUST_REQUIRED")
    try:
        pinned = get_trusted_audit_anchor(plan["proposal_sha256"])
        if (type(pinned) is not tuple or len(pinned) != 2 or
                type(pinned[0]) is not int or type(pinned[1]) is not str or
                pinned != (len(reviews), head)):
            raise GovernanceError("AUDIT_ANCHOR_MISMATCH")
        for review in reviews:
            statement = DOMAIN + _canonical({
                "proposal_sha256": review["proposal_sha256"],
                "evidence_sha256": review["evidence_sha256"],
                "actor_id": review["actor_id"],
                "role": review["role"], "verdict": review["verdict"]})
            if verify_role(statement, review["receipt"], review["actor_id"],
                           review["role"]) is not True:
                raise GovernanceError("ROLE_NOT_VERIFIED")
    except GovernanceError:
        raise
    except Exception as exc:
        raise GovernanceError("TRUST_PROVIDER_UNAVAILABLE") from exc
    rejected = any(r["verdict"] == "reject" for r in reviews)
    roles = {r["role"] for r in reviews if r["verdict"] == "approve-candidate"}
    distinct = {r["actor_id"] for r in reviews if r["verdict"] == "approve-candidate"}
    ready = not rejected and roles == ROLES and len(distinct) >= 2
    return {"schema": "palaco-recovery-governance-report/v12",
            "proposal_sha256": plan["proposal_sha256"],
            "review_head": head, "review_count": len(reviews),
            "candidate_review_complete": ready,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False}
