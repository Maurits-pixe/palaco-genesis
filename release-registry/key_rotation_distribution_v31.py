"""PALACO v31 key-rotation recovery and trust-distribution contract.

Read-only, fail-closed export of a fully committed, externally anchored v30
generation. A published bundle is NOT an independently trusted key store.
Verifiers must require a separately authenticated monotonic head and live v29
key revocation before accepting any public key. No private keys or deployment.
"""
import base64
import hashlib
import re
from contextlib import closing

from identity_key_rotation_v30 import IdentityKeyRotation, RotationError, HEX
from identity_session_lifecycle_v29 import IdentityLifecycleRegistry
from offline_stage import _canonical

SCHEMA = "palaco-key-distribution-candidate/v31"
DOMAIN = b"PALACO-KEY-DISTRIBUTION-v31\x00"
BUNDLE_KEYS = frozenset((
    "schema", "generation", "sequence", "head", "key_id",
    "public_key_b64", "fingerprint_sha256", "lifecycle_sequence",
    "lifecycle_head", "bundle_sha256", "authorization", "release",
    "production_release_enabled",
))


class DistributionError(ValueError):
    pass


def _b64key(value):
    if type(value) is not str or len(value) != 44:
        raise DistributionError("INVALID_PUBLIC_KEY")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise DistributionError("INVALID_PUBLIC_KEY") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise DistributionError("INVALID_PUBLIC_KEY")
    return raw


def _digest(document):
    return hashlib.sha256(DOMAIN + _canonical(document)).hexdigest()


def _current(rotation):
    """Read the same v30 transaction snapshot for event and state checks."""
    with closing(rotation._connect()) as db:
        db.execute("BEGIN")
        try:
            state = rotation._load(db)
            if state[2] < 1 or state[4] is not None:
                raise DistributionError("ROTATION_NOT_READY")
            row = db.execute(
                "SELECT new_key,fingerprint FROM key_rotation_events "
                "WHERE event='COMMIT' AND generation=?", (state[2],)).fetchone()
            if row is None or row[0] != state[3]:
                raise DistributionError("CORRUPT_ACTIVE_KEY")
            return state, row[1]
        finally:
            db.rollback()


class KeyRotationDistribution:
    """Prepare public-key bundles and inspect interrupted rotations.

    Independently authenticate BOTH rotation and revocation roots on every
    export and every verification, as well as current key enrollment/policy.
    External root callbacks must be monotonic remote trust providers, not
    equality checks against the supplied local files.
    """

    def __init__(self, *, rotation, lifecycle):
        if not isinstance(rotation, IdentityKeyRotation) or not isinstance(
                lifecycle, IdentityLifecycleRegistry):
            raise DistributionError("INVALID_DEPENDENCIES")
        self.rotation, self.lifecycle = rotation, lifecycle

    def recovery_inspection(self, *, verify_rotation_head):
        """Read-only state diagnosis: no automatic commit, retry or signing."""
        if not callable(verify_rotation_head):
            raise DistributionError("EXTERNAL_ANCHOR_REQUIRED")
        with closing(self.rotation._connect()) as db:
            db.execute("BEGIN")
            try:
                seq, head, gen, active, pending, _ = self.rotation._load(db)
            finally:
                db.rollback()
        try:
            trusted = verify_rotation_head(seq, head)
        except Exception as exc:
            raise DistributionError("ANCHOR_UNAVAILABLE") from exc
        if trusted is not True:
            raise DistributionError("UNTRUSTED_ROTATION")
        return {
            "schema": "palaco-key-recovery-inspection/v31",
            "sequence": seq, "head": head, "generation": gen,
            "state": "PENDING_EXTERNAL_REVIEW" if pending is not None else (
                "LOCALLY_COMMITTED" if gen > 0 else "NO_GENERATION"),
            "manual_review_required": pending is not None,
            "active_key": active if pending is None else None,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }

    def candidate(self, *, key_id, public_key, verify_rotation_head,
                  verify_lifecycle_head, verify_active_key):
        """Export public key only after strict independent live controls.

        This is a CANDIDATE for distribution, not a signed authorization.
        Trust consumers must verify it afresh and pin the bytes separately.
        """
        if type(key_id) is not str or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,128}", key_id):
            raise DistributionError("INVALID_KEY_ID")
        if type(public_key) is not bytes or len(public_key) != 32:
            raise DistributionError("INVALID_PUBLIC_KEY")
        if not all(callable(x) for x in (
                verify_rotation_head, verify_lifecycle_head,
                verify_active_key)):
            raise DistributionError("EXTERNAL_TRUST_REQUIRED")
        state, fp = _current(self.rotation)
        seq, head, generation, active, pending, retired = state
        if active != key_id or key_id in retired:
            raise DistributionError("NOT_CURRENT_KEY")
        if hashlib.sha256(public_key).hexdigest() != fp:
            raise DistributionError("PUBLIC_KEY_MISMATCH")
        try:
            trusted_rotation = verify_rotation_head(seq, head)
            revoked = self.lifecycle.verified_snapshot(
                verify_external_head=verify_lifecycle_head)
            enrolled = verify_active_key(key_id, public_key, generation)
        except Exception as exc:
            raise DistributionError("TRUST_UNAVAILABLE") from exc
        if trusted_rotation is not True or enrolled is not True or (
                "REVOKE_SIGNING_KEY", key_id) in revoked:
            raise DistributionError("UNTRUSTED_KEY")
        l_seq, l_head = self.lifecycle.current_local()
        # A second external check detects ordinary mid-export changes. This
        # cannot guarantee cross-DB atomicity; production needs signed epochs.
        if verify_lifecycle_head(l_seq, l_head) is not True or (
                self.rotation.inspect_local()["sequence"] != seq or
                self.lifecycle.current_local() != (l_seq, l_head)):
            raise DistributionError("TRUST_CHANGED")
        document = {
            "schema": SCHEMA, "generation": generation,
            "sequence": seq, "head": head, "key_id": key_id,
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            "fingerprint_sha256": fp,
            "lifecycle_sequence": l_seq, "lifecycle_head": l_head,
            "authorization": "DENY", "release": "HOLD",
            "production_release_enabled": False,
        }
        document["bundle_sha256"] = _digest(document)
        return document


def inspect_candidate(bundle, *, verify_rotation_head,
                      verify_lifecycle_head, check_active_key):
    """Verify candidate as diagnostic only; NEVER treat it as signer authority.

    Caller must have independently secured the trust providers, and must
    separately pin the public key. A self-reported bundle/hash is insufficient.
    """
    if not all(callable(x) for x in (
            verify_rotation_head, verify_lifecycle_head, check_active_key)):
        return False
    try:
        if (type(bundle) is not dict or set(bundle) != BUNDLE_KEYS or
                bundle["schema"] != SCHEMA or
                bundle["authorization"] != "DENY" or
                bundle["release"] != "HOLD" or
                bundle["production_release_enabled"] is not False):
            return False
        for key in ("generation", "sequence", "lifecycle_sequence"):
            if type(bundle[key]) is not int or bundle[key] < 0:
                return False
        if bundle["generation"] < 1 or bundle["sequence"] < 2:
            return False
        for key in ("head", "fingerprint_sha256", "lifecycle_head",
                    "bundle_sha256"):
            if type(bundle[key]) is not str or not HEX.fullmatch(bundle[key]):
                return False
        if type(bundle["key_id"]) is not str or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,128}", bundle["key_id"]):
            return False
        public = _b64key(bundle["public_key_b64"])
        if hashlib.sha256(public).hexdigest() != bundle["fingerprint_sha256"]:
            return False
        unsigned = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
        if _digest(unsigned) != bundle["bundle_sha256"]:
            return False
        return (
            verify_rotation_head(bundle["sequence"], bundle["head"]) is True and
            verify_lifecycle_head(
                bundle["lifecycle_sequence"], bundle["lifecycle_head"]) is True and
            check_active_key(bundle["key_id"], public,
                             bundle["generation"]) is True)
    except Exception:
        return False
