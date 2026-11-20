"""PALACO v9 candidate: strictly forward-only key-policy ledger.

Local structural and cryptographic hash consistency is NOT authentic provenance.
A separate trusted, monotonic anchor is mandatory for any trust decision.
No keys are created; no signing, revocation service, or authority is granted.
"""
import hashlib
import json

from key_registry_v8 import SCHEMA as REGISTRY_SCHEMA, _snapshot, snapshot_digest
from offline_stage import _canonical

SCHEMA = "palaco-policy-ledger/v9"
EVENT_PREFIX = b"PALACO-POLICY-LEDGER-v9:EVENT\x00"
GENESIS = hashlib.sha256(b"PALACO-POLICY-LEDGER-v9:GENESIS").hexdigest()
MAX_ENTRIES = 10000


class LedgerError(ValueError):
    pass


def _snapshot_keys(snapshot):
    _snapshot(snapshot)
    return {entry["key_id"]: entry for entry in snapshot["keys"]}


def _forward(before, after):
    """No removal, key mutation, scope widening or revoked-key resurrection."""
    prior, updated = _snapshot_keys(before), _snapshot_keys(after)
    if after["version"] != before["version"] + 1:
        raise LedgerError("INVALID_REGISTRY_VERSION")
    if not set(prior).issubset(updated):
        raise LedgerError("KEY_REMOVAL_FORBIDDEN")
    for key_id, old in prior.items():
        new = updated[key_id]
        if old["public_key_b64"] != new["public_key_b64"]:
            raise LedgerError("KEY_MATERIAL_CHANGE_FORBIDDEN")
        if old["scopes"] != new["scopes"]:
            raise LedgerError("SCOPE_CHANGE_REQUIRES_NEW_KEY")
        if old["status"] == "revoked" and new["status"] != "revoked":
            raise LedgerError("REVOCATION_TERMINAL")
    return True


def event_digest(event):
    if type(event) is not dict:
        raise LedgerError("INVALID_EVENT")
    return hashlib.sha256(EVENT_PREFIX + _canonical(event)).hexdigest()


def _check_event(event):
    if type(event) is not dict or set(event) != {
        "schema", "sequence", "previous", "before_sha256",
        "after_sha256", "before", "after"
    } or event["schema"] != SCHEMA:
        raise LedgerError("INVALID_EVENT")
    if type(event["sequence"]) is not int or event["sequence"] < 1:
        raise LedgerError("INVALID_SEQUENCE")
    if type(event["previous"]) is not str or len(event["previous"]) != 64:
        raise LedgerError("INVALID_PREVIOUS")
    try:
        before_digest = snapshot_digest(event["before"])
        after_digest = snapshot_digest(event["after"])
    except (ValueError, TypeError, KeyError) as exc:
        raise LedgerError("INVALID_SNAPSHOT") from exc
    if event["before_sha256"] != before_digest or event["after_sha256"] != after_digest:
        raise LedgerError("SNAPSHOT_DIGEST_MISMATCH")
    _forward(event["before"], event["after"])


def replay_ledger(events, *, expected_anchor=None):
    """Reconstruct head; never claim that a supplied anchor is trusted."""
    if type(events) not in (list, tuple) or len(events) > MAX_ENTRIES:
        raise LedgerError("INVALID_LEDGER")
    head, prior_snapshot = GENESIS, None
    for index, event in enumerate(events, start=1):
        _check_event(event)
        if event["sequence"] != index or event["previous"] != head:
            raise LedgerError("BROKEN_LEDGER_CHAIN")
        if prior_snapshot is not None and event["before"] != prior_snapshot:
            raise LedgerError("DISCONTINUOUS_REGISTRY_HISTORY")
        prior_snapshot = event["after"]
        head = event_digest(event)
    if expected_anchor is not None and expected_anchor != (len(events), head):
        raise LedgerError("ANCHOR_MISMATCH")
    return head, prior_snapshot


def propose_event(history, before, after, *, expected_head):
    """Build one candidate event, never mutate history or activate policy."""
    head, current = replay_ledger(history)
    if type(expected_head) is not str or head != expected_head:
        raise LedgerError("STALE_CHECKPOINT")
    if current is not None and before != current:
        raise LedgerError("HISTORY_STATE_MISMATCH")
    _forward(before, after)
    event = {
        "schema": SCHEMA, "sequence": len(history) + 1,
        "previous": head, "before_sha256": snapshot_digest(before),
        "after_sha256": snapshot_digest(after),
        "before": before, "after": after
    }
    _check_event(event)
    # Freeze caller-owned objects so later mutations cannot change a proposal.
    frozen = json.loads(_canonical(event))
    return frozen, event_digest(frozen)


def verify_anchored_ledger(events, *, get_trusted_anchor, verify_policy):
    """Fail closed when an independent anchor or current policy is missing.

    get_trusted_anchor() MUST read from an authenticated external monotonic
    source, not from events. verify_policy(sequence, head) MUST independently
    check current policy, revocation and freshness. Return no permissions.
    """
    if not callable(get_trusted_anchor) or not callable(verify_policy):
        raise LedgerError("EXTERNAL_TRUST_REQUIRED")
    if type(events) not in (list, tuple) or not events:
        raise LedgerError("EMPTY_LEDGER_NOT_TRUSTED")
    head, snapshot = replay_ledger(events)
    try:
        anchor = get_trusted_anchor()
        if type(anchor) is not tuple or len(anchor) != 2 or (
                type(anchor[0]) is not int or type(anchor[1]) is not str or
                anchor != (len(events), head)):
            raise LedgerError("ANCHOR_MISMATCH")
        if verify_policy(len(events), head) is not True:
            raise LedgerError("POLICY_UNVERIFIED")
    except LedgerError:
        raise
    except Exception as exc:
        raise LedgerError("EXTERNAL_TRUST_UNAVAILABLE") from exc
    return {
        "schema": "palaco-policy-ledger-inspection/v9",
        "sequence": len(events), "head": head,
        "registry_digest": snapshot_digest(snapshot) if snapshot is not None else None,
        "external_callbacks_accepted": True, "release": "HOLD",
        "authorization": "DENY", "production_release_enabled": False
    }
