"""PALACO v33 device trust and synchronization recovery (DRAFT / HOLD).

This module verifies Ed25519 device receipts for the v32 acknowledgment
contract, and inspects interrupted syncs read-only. Device key enrollment,
revocation, monotonic anchoring and trust distribution are EXTERNAL.
No key installation, recovery execution, authorization, or issuance.
"""
import base64
import binascii
from contextlib import closing
import hashlib
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from offline_stage import _canonical
from secure_trust_sync_v32 import TrustSyncRegistry, SyncError

PROOF_SCHEMA = "palaco-device-acknowledgment-proof/v33"
DOMAIN = b"PALACO-DEVICE-ACKNOWLEDGMENT-v33\x00"
FIELDS = frozenset(("schema", "module", "key_id", "statement_sha256",
                   "signature_b64"))
IDENTITY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_PROOF_LENGTH = 2048
MAX_PENDING = 8


class DeviceTrustError(ValueError):
    pass


def _id(item):
    return type(item) is str and IDENTITY.fullmatch(item) is not None


def _public_key(value):
    return type(value) is bytes and len(value) == 32


class DeviceProofVerifier:
    """Callable verify_device(module, statement, proof) for v32.

    resolve_device_public_key(module,key_id) MUST obtain a pinned key from
    independently authenticated device enrollment. current_device_policy
    must check live enrollment, role, module scope, device revocation and
    signing-key revocation. Both are external and absent from this module.
    """

    def __init__(self, *, resolve_device_public_key, current_device_policy):
        if not callable(resolve_device_public_key) or not callable(
                current_device_policy):
            raise DeviceTrustError("EXTERNAL_DEVICE_TRUST_REQUIRED")
        self._resolve = resolve_device_public_key
        self._policy = current_device_policy

    def __call__(self, module, statement, proof):
        try:
            if (not _id(module) or type(statement) is not bytes or
                    not 1 <= len(statement) <= 8192 or
                    type(proof) is not str or not 1 <= len(proof) <= MAX_PROOF_LENGTH):
                return False
            doc = json.loads(proof)
            if (type(doc) is not dict or set(doc) != FIELDS or
                    doc["schema"] != PROOF_SCHEMA or
                    _canonical(doc).decode("ascii") != proof or
                    not _id(doc["module"]) or not _id(doc["key_id"]) or
                    doc["module"] != module or
                    type(doc["statement_sha256"]) is not str or
                    not SHA.fullmatch(doc["statement_sha256"]) or
                    doc["statement_sha256"] != hashlib.sha256(statement).hexdigest()):
                return False
            encoded = doc["signature_b64"]
            if type(encoded) is not str or len(encoded) != 88:
                return False
            sig = base64.b64decode(encoded, validate=True)
            if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != encoded:
                return False
            key = self._resolve(module, doc["key_id"])
            if not _public_key(key):
                return False
            signed = _canonical({
                "schema": PROOF_SCHEMA, "module": module,
                "key_id": doc["key_id"],
                "statement_sha256": doc["statement_sha256"],
            })
            Ed25519PublicKey.from_public_bytes(key).verify(sig, DOMAIN + signed)
            # Never rely on signed bytes alone; active enrollment is checked
            # after signature verification and must return literal True.
            return self._policy(module, doc["key_id"],
                                doc["statement_sha256"]) is True
        except Exception:
            return False


class DeviceSyncRecoveryInspector:
    """Read-only diagnostics of v32 journal/challenges for one module.

    No access to secret challenges (only hashes persisted by v32). Does not
    consume, delete, retry, sign or activate any key. A remotely attested
    monotonic receipt head is mandatory for even a diagnostic response.
    """

    def __init__(self, *, registry, max_pending=MAX_PENDING):
        if not isinstance(registry, TrustSyncRegistry):
            raise DeviceTrustError("INVALID_REGISTRY")
        if type(max_pending) is not int or not 1 <= max_pending <= 100:
            raise DeviceTrustError("INVALID_PENDING_LIMIT")
        self.registry, self.max_pending = registry, max_pending

    def inspect(self, module, *, verify_sync_head):
        if not _id(module):
            raise DeviceTrustError("INVALID_MODULE")
        if not callable(verify_sync_head):
            raise DeviceTrustError("EXTERNAL_ANCHOR_REQUIRED")
        with closing(self.registry._connect()) as db:
            db.execute("BEGIN")
            try:
                generation, head, _, _ = self.registry._latest(db, module)
                challenges = db.execute(
                    "SELECT generation,prior_generation,prior_receipt_hash,"
                    "consumed FROM sync_challenges WHERE module=?",
                    (module,)).fetchall()
            finally:
                db.rollback()
        try:
            anchored = verify_sync_head(module, generation, head)
        except Exception as exc:
            raise DeviceTrustError("ANCHOR_UNAVAILABLE") from exc
        if anchored is not True:
            raise DeviceTrustError("UNTRUSTED_SYNC_ROOT")
        pending = 0
        stale = 0
        for target, prior, prior_hash, consumed in challenges:
            if (type(target) is not int or type(prior) is not int or
                    type(prior_hash) is not str or not (
                        SHA.fullmatch(prior_hash) or prior_hash == "GENESIS") or
                    type(consumed) is not int or consumed not in (0, 1)):
                raise DeviceTrustError("CORRUPT_CHALLENGE_JOURNAL")
            if consumed == 0:
                pending += 1
                if (target != generation + 1 or prior != generation or
                        prior_hash != head):
                    stale += 1
        # Unbounded pending challenges are not healthy. Still report only
        # count/status and force manual review; do not reveal bearer hashes.
        state = ("EXCESS_PENDING" if pending > self.max_pending else
                 "STALE_CHALLENGES" if stale > 0 else
                 "PENDING_EXTERNAL_REVIEW" if pending > 0 else
                 "ACKNOWLEDGED_LOCALLY" if generation > 0 else
                 "NO_RECEIPT")
        return {
            "schema": "palaco-device-sync-recovery-inspection/v33",
            "module": module, "generation": generation,
            "pending_challenges": pending, "stale_challenges": stale,
            "state": state, "manual_review_required": pending > 0,
            "device_proof_verified": False,
            "key_installed": False, "authorization": "DENY",
            "release": "HOLD", "production_release_enabled": False,
        }
