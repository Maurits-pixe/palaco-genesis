"""Atomic local revision-and-replay index tests."""
import base64
import copy
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("atomic_gate", ROOT / "tools" / "atomic_reviewer_replay.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class AtomicReviewerReplayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "single.sqlite"
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
        signer_pub = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        issuer_pub = self.issuer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.signer_id = hashlib.sha256(signer_pub).hexdigest()
        self.issuer_id = hashlib.sha256(issuer_pub).hexdigest()
        self.keys = {self.signer_id: signer_pub}
        self.roots = {self.issuer_id: issuer_pub}

    def registry(self, revision=5, revoked=False):
        snapshot = {"schema_version": "0.1.0", "revision": revision, "reviewers": [{
            "reviewer_id": "reviewer-a", "key_fingerprint": self.signer_id,
            "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
            "revoked": revoked
        }]}
        signature = self.issuer.sign(b"PALACO-REVIEWER-REGISTRY-V1\x00" + mod.reviewers.canonical(snapshot))
        return {"snapshot": snapshot, "issuer_key_id": self.issuer_id,
                "issuer_signature_b64": base64.b64encode(signature).decode()}

    def item(self, identifier="rec-a"):
        payload = {"content": identifier}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        metadata = {"schema_version": "0.1.0", "record_id": identifier,
                    "lineage_id": "lineage-a", "payload_sha256": digest}
        signature = self.signer.sign(mod.signed.canonical_metadata(metadata))
        return {"reviewer_id": "reviewer-a", "candidate": {**metadata, "payload": payload},
                "envelope": {"metadata": metadata, "key_id": self.signer_id,
                             "signature_b64": base64.b64encode(signature).decode()}}

    def check(self, registry=None, items=None, minimum=5):
        result = mod.inspect_and_index(
            self.db, [self.item()] if items is None else items,
            self.registry() if registry is None else registry,
            self.roots, self.keys, "2026-11-22T04:00:00Z", minimum
        )
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["evidence_verified"])
        self.assertEqual(result["release_gate"], "HOLD")
        return result

    def test_both_tables_in_single_database(self):
        result = self.check()
        self.assertEqual(result["decisions"][0]["state"], "pending-review")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reviewer_revision_floor").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM seen_candidate_ids").fetchone()[0], 1)

    def test_replay_quarantined(self):
        self.check()
        self.assertEqual(self.check()["decisions"][0]["reason"], "previously-seen-record-id")

    def test_rollback_rejected_without_replay_update(self):
        self.check()
        result = self.check(self.registry(4), [self.item("rec-b")], minimum=4)
        self.assertEqual(result["decisions"][0]["reason"], "registry-rollback")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM seen_candidate_ids").fetchone()[0], 1)

    def test_equivocation_rejected(self):
        self.check()
        result = self.check(self.registry(5, revoked=True), [self.item("rec-b")])
        self.assertEqual(result["decisions"][0]["reason"], "registry-equivocation")

    def test_higher_revocation_blocks_record(self):
        self.check()
        result = self.check(self.registry(6, revoked=True), [self.item("rec-b")])
        self.assertEqual(result["decisions"][0]["reason"], "reviewer-revoked")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT revision FROM reviewer_revision_floor").fetchone()[0], 6)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM seen_candidate_ids").fetchone()[0], 1)

    def test_bad_issuer_never_creates_database(self):
        registry = self.registry()
        registry["snapshot"]["revision"] = 99
        self.assertEqual(self.check(registry)["decisions"][0]["reason"], "invalid-snapshot-signature")
        self.assertFalse(self.db.exists())

    def test_bad_candidate_never_indexed(self):
        item = self.item()
        item["candidate"]["payload"]["content"] = "tampered"
        result = self.check(items=[item])
        self.assertEqual(result["decisions"][0]["reason"], "candidate-binding-failed")
        self.assertEqual(self.check()["decisions"][0]["state"], "pending-review")

    def test_batch_duplicate_both_quarantined(self):
        item = self.item()
        result = self.check(items=[item, copy.deepcopy(item)])
        self.assertEqual([d["reason"] for d in result["decisions"]], ["duplicate-record-id"] * 2)

    def test_external_minimum_enforced(self):
        result = self.check(minimum=6)
        self.assertEqual(result["decisions"][0]["reason"], "stale-registry-revision")
        self.assertFalse(self.db.exists())

    def test_revision_and_replay_have_audit_events(self):
        self.check()
        result = mod.audit.verify(self.db)
        self.assertTrue(result["chain_valid"])
        self.assertEqual(result["events_checked"], 2)

    def test_replay_rejection_does_not_extend_audit(self):
        self.check()
        prior = mod.audit.verify(self.db)["head_hash"]
        self.check()
        after = mod.audit.verify(self.db)
        self.assertEqual(after["head_hash"], prior)
        self.assertEqual(after["events_checked"], 2)

    def test_revocation_update_audited_but_not_indexed(self):
        self.check()
        self.check(self.registry(6, revoked=True), [self.item("rec-b")])
        result = mod.audit.verify(self.db)
        self.assertTrue(result["chain_valid"])
        self.assertEqual(result["events_checked"], 3)

    def test_input_unchanged(self):
        records = [self.item()]
        previous = copy.deepcopy(records)
        self.check(items=records)
        self.assertEqual(records, previous)


if __name__ == "__main__":
    unittest.main()
