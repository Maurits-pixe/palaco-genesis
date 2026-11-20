"""Synthetic v33 cryptographic device proof and interrupted-sync tests.

Private Ed25519 key is an ephemeral TEST FIXTURE only. No production device
enrollment, signer, trusted remote anchor or key installation is exercised.
"""
import base64
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from device_trust_recovery_v33 import (
    DOMAIN, PROOF_SCHEMA, DeviceProofVerifier,
    DeviceSyncRecoveryInspector, DeviceTrustError,
)
from identity_key_rotation_v30 import IdentityKeyRotation, GENESIS
from identity_session_lifecycle_v29 import IdentityLifecycleRegistry
from key_rotation_distribution_v31 import KeyRotationDistribution
from offline_stage import _canonical
from secure_trust_sync_v32 import TrustSyncRegistry


class DeviceTrustTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name)
        self.registry = TrustSyncRegistry(folder / "sync.sqlite")
        self.module = "rio"
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.live = True
        self.verifier = DeviceProofVerifier(
            resolve_device_public_key=lambda mod, kid:
                self.public if (mod, kid) == ("rio", "device-key-1") else None,
            current_device_policy=lambda *_: self.live)
        self.statement = _canonical({
            "schema": "palaco-trust-sync-receipt/v32",
            "module": "rio", "challenge_sha256": "a"*64,
            "generation": 1, "bundle_sha256": "b"*64,
            "previous_receipt": "GENESIS",
        })
        self.inspector = DeviceSyncRecoveryInspector(registry=self.registry)

    def proof(self, *, statement=None, module="rio", key_id="device-key-1",
              signer=None, extras=None):
        st = self.statement if statement is None else statement
        claim = {
            "schema": PROOF_SCHEMA, "module": module, "key_id": key_id,
            "statement_sha256": hashlib.sha256(st).hexdigest(),
        }
        signing = self.signer if signer is None else signer
        data = dict(claim, signature_b64=base64.b64encode(
            signing.sign(DOMAIN + _canonical(claim))).decode("ascii"))
        if extras:
            data.update(extras)
        return _canonical(data).decode("ascii")

    def inspect(self, **kwargs):
        args = dict(verify_sync_head=lambda _, n, h: (n, h) == (0, "GENESIS"))
        args.update(kwargs)
        return self.inspector.inspect(self.module, **args)

    def seed_challenge(self, *, generation=1, prior=0, head="GENESIS",
                       consumed=0, token="a"*64):
        with sqlite3.connect(self.registry.path) as db:
            db.execute(
                "INSERT INTO sync_challenges(token_hash,module,generation,"
                "bundle_hash,prior_generation,prior_receipt_hash,consumed)"
                " VALUES(?,?,?,?,?,?,?)",
                (token, self.module, generation, "b"*64,
                 prior, head, consumed))

    def test_signature_verifies(self):
        self.assertTrue(self.verifier("rio", self.statement, self.proof()))

    def test_wrong_signature_denied(self):
        other = Ed25519PrivateKey.generate()
        self.assertFalse(self.verifier(
            "rio", self.statement, self.proof(signer=other)))

    def test_statement_change_denied(self):
        self.assertFalse(self.verifier(
            "rio", self.statement + b" ", self.proof()))

    def test_module_change_denied(self):
        self.assertFalse(self.verifier(
            "citadel", self.statement, self.proof()))

    def test_unregistered_key_denied(self):
        self.assertFalse(self.verifier(
            "rio", self.statement, self.proof(key_id="foreign")))

    def test_revoked_device_denied(self):
        self.live = False
        self.assertFalse(self.verifier("rio", self.statement, self.proof()))

    def test_truthy_nonboolean_policy_denied(self):
        self.live = 1
        self.assertFalse(self.verifier("rio", self.statement, self.proof()))

    def test_unavailable_policy_denied(self):
        def fail(*_):
            raise ConnectionError("device registry unavailable")
        verifier = DeviceProofVerifier(
            resolve_device_public_key=lambda *_: self.public,
            current_device_policy=fail)
        self.assertFalse(verifier("rio", self.statement, self.proof()))

    def test_unavailable_key_provider_denied(self):
        def fail(*_):
            raise ConnectionError("enrollment unavailable")
        verifier = DeviceProofVerifier(
            resolve_device_public_key=fail,
            current_device_policy=lambda *_: True)
        self.assertFalse(verifier("rio", self.statement, self.proof()))

    def test_malformed_proof_denied(self):
        self.assertFalse(self.verifier("rio", self.statement, "not-json"))

    def test_noncanonical_proof_denied(self):
        self.assertFalse(self.verifier("rio", self.statement, self.proof() + " "))

    def test_extra_proof_field_denied(self):
        self.assertFalse(self.verifier("rio", self.statement,
                                       self.proof(extras={"approved": True})))

    def test_invalid_signature_encoding_denied(self):
        import json
        data = json.loads(self.proof())
        data["signature_b64"] = "!"*88
        self.assertFalse(self.verifier(
            "rio", self.statement, _canonical(data).decode("ascii")))

    def test_invalid_statement_type_denied(self):
        self.assertFalse(self.verifier("rio", "unsafe", self.proof()))

    def test_missing_provider_rejected(self):
        with self.assertRaisesRegex(DeviceTrustError, "EXTERNAL_DEVICE_TRUST_REQUIRED"):
            DeviceProofVerifier(
                resolve_device_public_key=None,
                current_device_policy=lambda *_: True)

    def test_genesis_diagnostics(self):
        report = self.inspect()
        self.assertEqual(report["state"], "NO_RECEIPT")
        self.assertFalse(report["key_installed"])
        self.assertEqual(report["authorization"], "DENY")

    def test_pending_requires_review(self):
        self.seed_challenge()
        report = self.inspect()
        self.assertEqual(report["state"], "PENDING_EXTERNAL_REVIEW")
        self.assertEqual(report["pending_challenges"], 1)
        self.assertTrue(report["manual_review_required"])

    def test_stale_pending_detected(self):
        self.seed_challenge(generation=3)
        report = self.inspect()
        self.assertEqual(report["state"], "STALE_CHALLENGES")
        self.assertEqual(report["stale_challenges"], 1)

    def test_pending_limit_detected(self):
        self.inspector = DeviceSyncRecoveryInspector(
            registry=self.registry, max_pending=1)
        self.seed_challenge(token="a"*64)
        self.seed_challenge(token="b"*64)
        self.assertEqual(self.inspect()["state"], "EXCESS_PENDING")

    def test_consumed_not_pending(self):
        self.seed_challenge(consumed=1)
        self.assertEqual(self.inspect()["pending_challenges"], 0)

    def test_no_secret_hash_in_report(self):
        self.seed_challenge(token="a"*64)
        self.assertNotIn("a"*64, str(self.inspect()))

    def test_untrusted_remote_root_denied(self):
        with self.assertRaisesRegex(DeviceTrustError, "UNTRUSTED_SYNC_ROOT"):
            self.inspect(verify_sync_head=lambda *_: False)

    def test_nonboolean_remote_root_denied(self):
        with self.assertRaisesRegex(DeviceTrustError, "UNTRUSTED_SYNC_ROOT"):
            self.inspect(verify_sync_head=lambda *_: 1)

    def test_unavailable_root_denied(self):
        def fail(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(DeviceTrustError, "ANCHOR_UNAVAILABLE"):
            self.inspect(verify_sync_head=fail)

    def test_missing_root_denied(self):
        with self.assertRaisesRegex(DeviceTrustError, "EXTERNAL_ANCHOR_REQUIRED"):
            self.inspect(verify_sync_head=None)

    def test_corrupted_pending_journal_denied(self):
        self.seed_challenge(head="invalid")
        with self.assertRaisesRegex(DeviceTrustError, "CORRUPT_CHALLENGE_JOURNAL"):
            self.inspect()

    def test_restart_preserves_pending_diagnostics(self):
        self.seed_challenge()
        self.registry = TrustSyncRegistry(self.registry.path)
        self.inspector = DeviceSyncRecoveryInspector(registry=self.registry)
        self.assertEqual(self.inspect()["pending_challenges"], 1)

    def test_wrong_registry_rejected(self):
        with self.assertRaisesRegex(DeviceTrustError, "INVALID_REGISTRY"):
            DeviceSyncRecoveryInspector(registry=object())

    def test_bad_limit_rejected(self):
        with self.assertRaisesRegex(DeviceTrustError, "INVALID_PENDING_LIMIT"):
            DeviceSyncRecoveryInspector(registry=self.registry, max_pending=True)

    def test_no_recovery_execution(self):
        for name in ("install", "activate", "commit", "revoke", "retry"):
            self.assertFalse(hasattr(self.inspector, name))

    def test_v32_cryptographic_ack_integration(self):
        """Exercise actual v32 callback binding to Ed25519 receipt statement."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rotation = IdentityKeyRotation(root / "rot.sqlite")
            lifecycle = IdentityLifecycleRegistry(root / "life.sqlite")
            distribution = KeyRotationDistribution(
                rotation=rotation, lifecycle=lifecycle)
            rot_root = [0, GENESIS]
            def check_rot(seq, head):
                return (seq, head) == tuple(rot_root)
            first_key = b"x"*32
            rotation.prepare(
                old_key="bootstrap", new_key="key-1", public_key=first_key,
                expected_sequence=0, expected_head=GENESIS,
                verify_predecessor=check_rot, check_policy=lambda *_: True)
            head = rotation.inspect_local()
            rot_root[:] = [head["sequence"], head["head"]]
            rotation.commit(
                old_key="bootstrap", new_key="key-1", public_key=first_key,
                expected_sequence=head["sequence"], expected_head=head["head"],
                verify_predecessor=check_rot, check_policy=lambda *_: True)
            head = rotation.inspect_local()
            rot_root[:] = [head["sequence"], head["head"]]
            life = lifecycle.current_local()
            def check_life(n, h):
                return (n, h) == life
            bundle = distribution.candidate(
                key_id="key-1", public_key=first_key,
                verify_rotation_head=check_rot,
                verify_lifecycle_head=check_life,
                verify_active_key=lambda *_: True)
            kwargs = dict(
                verify_sync_head=lambda m, n, h: (m,n,h) == (
                    "rio",0,"GENESIS"),
                verify_rotation_head=check_rot,
                verify_lifecycle_head=check_life,
                check_active_key=lambda *_: True)
            issued = self.registry.stage("rio", bundle, **kwargs)
            token = issued["challenge"]
            statement = _canonical({
                "schema": "palaco-trust-sync-receipt/v32",
                "module": "rio",
                "challenge_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "generation": 1, "bundle_sha256": bundle["bundle_sha256"],
                "previous_receipt": "GENESIS",
            })
            receipt = self.registry.acknowledge(
                "rio", bundle, token, self.proof(statement=statement),
                verify_device=self.verifier, **kwargs)
            self.assertTrue(receipt["device_acknowledged"])
            self.assertFalse(receipt["key_installed"])
            self.assertEqual(receipt["release"], "HOLD")


if __name__ == "__main__":
    unittest.main()
