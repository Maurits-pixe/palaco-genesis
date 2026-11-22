"""Replay quarantine and conflicting signed recovery review tests."""
import base64
import copy
import hashlib
import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_log", ROOT / "tools" / "signed_review_replay_register.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedReviewReplayRegisterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "reviews.sqlite"
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
        key = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        root = self.issuer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(key).hexdigest()
        self.issuer_id = hashlib.sha256(root).hexdigest()
        self.keys, self.roots = {self.key_id: key}, {self.issuer_id: root}
        self.review = {"reviewer_id": "reviewer-a", "decision": "request-review",
                       "reason": "Further independent security verification",
                       "reviewed_at_utc": "2026-11-22T05:00:00Z"}
        self.dossier = {
            "schema_version": "0.1.0", "record_type": "local-recovery-review-dossier",
            "assessment_state": "pending-review", "assessment_reason": "local-consistency-only",
            "witness_sha256": "1" * 64, "issuer_key_id": self.issuer_id,
            "witness_sequence": 1, "witness_head": "2" * 64,
            "manual_review": dict(self.review),
            "required_follow_up": "independent-security-review",
        }
        self.registry = self.registry_envelope()
        self.env = self.signed_envelope(self.dossier)

    def registry_envelope(self):
        snapshot = {"schema_version": "0.1.0", "revision": 7, "reviewers": [{
            "reviewer_id": "reviewer-a", "key_fingerprint": self.key_id,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z", "revoked": False
        }]}
        signature = self.issuer.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00"
                                     + mod.signed.reviewers.canonical(snapshot))
        return {"snapshot": snapshot, "issuer_key_id": self.issuer_id,
                "issuer_signature_b64": base64.b64encode(signature).decode()}

    def signed_envelope(self, dossier):
        digest = hashlib.sha256(b"PALACO-RECOVERY-DOSSIER-V1\x00"
                                + mod.signed.dossiers.canonical(dossier)).hexdigest()
        declaration = {"schema_version": "0.1.0", "dossier_sha256": digest,
                       **dossier["manual_review"]}
        sig = self.signer.sign(mod.signed.DOMAIN + mod.signed.canonical_declaration(declaration))
        return {"declaration": declaration, "key_id": self.key_id,
                "signature_b64": base64.b64encode(sig).decode()}

    def check(self, dossier=None, env=None, revoked=None, roots=None, revision=7):
        out = mod.inspect_and_register(
            self.db, self.dossier if dossier is None else dossier,
            self.env if env is None else env, self.keys,
            set() if revoked is None else revoked,
            self.registry, self.roots if roots is None else roots,
            "2026-11-22T05:00:00Z", revision
        )
        self.assertEqual(out["release_gate"], "HOLD")
        self.assertFalse(out["authorization_granted"])
        self.assertFalse(out["recovery_approved"])
        self.assertFalse(out["automatic_restore"])
        return out

    def test_first_review_pending_only(self):
        r = self.check()
        self.assertTrue(r["review_recorded"])
        self.assertEqual(r["state"], "pending-review")

    def test_replay_identical_quarantined(self):
        self.check()
        self.assertEqual(self.check()["reason"], "previously-seen-signed-review")

    def test_conflicting_decision_same_dossier_rejected(self):
        self.check()
        new = copy.deepcopy(self.dossier)
        new["manual_review"]["decision"] = "defer"
        # Same logical dossier is still bound by the exact digest, so tampering
        # must be denied before indexing.
        self.assertEqual(self.check(dossier=new)["reason"], "dossier-binding-failed")

    def test_mutated_signature_rejected_before_replay(self):
        forged = copy.deepcopy(self.env)
        forged["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(env=forged)["reason"], "invalid-review-signature")
        self.assertFalse(self.db.exists())

    def test_revoked_reviewer_rejected_before_replay(self):
        self.assertEqual(self.check(revoked={self.key_id})["reason"], "reviewer-key-revoked")
        self.assertFalse(self.db.exists())

    def test_unknown_root_rejected(self):
        self.assertEqual(self.check(roots={})["reason"], "untrusted-issuer")
        self.assertFalse(self.db.exists())

    def test_stale_revision_rejected(self):
        self.assertEqual(self.check(revision=8)["reason"], "stale-registry-revision")
        self.assertFalse(self.db.exists())

    def test_read_only_inspect(self):
        self.assertIsNone(mod.inspect(self.db, self.env["declaration"]["dossier_sha256"], "reviewer-a"))
        self.check()
        value = mod.inspect(self.db, self.env["declaration"]["dossier_sha256"], "reviewer-a")
        self.assertEqual(value["key_id"], self.key_id)

    def test_no_raw_review_text_stored(self):
        self.check()
        with sqlite3.connect(self.db) as conn:
            rows = conn.execute("SELECT * FROM observed_recovery_reviews").fetchall()
        self.assertNotIn(self.review["reason"], str(rows))

    def test_other_dossier_registers_independently(self):
        self.check()
        other = copy.deepcopy(self.dossier)
        other["assessment_reason"] = "another-case"
        otherenv = self.signed_envelope(other)
        self.assertEqual(self.check(other, otherenv)["state"], "pending-review")

    def test_same_dossier_same_reviewer_is_unique(self):
        self.check()
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM observed_recovery_reviews"
            ).fetchone()[0], 1)

    def test_input_not_mutated(self):
        old = copy.deepcopy(self.env)
        self.check()
        self.assertEqual(self.env, old)


if __name__ == "__main__":
    unittest.main()
