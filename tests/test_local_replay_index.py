"""Persistence and replay regression tests for local UNTRUSTED SQLite index."""
import copy
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("replay_index", ROOT / "tools" / "local_replay_index.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def record(identifier="r1", value="alpha"):
    payload = {"content": value}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "record_id": identifier, "lineage_id": "lineage-1",
        "payload": payload, "payload_sha256": digest, "schema_version": "0.1.0",
    }


class LocalReplayIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "index.sqlite"

    def check(self, items):
        result = module.index_candidates(self.db, items)
        self.assertIs(result["authorization_granted"], False)
        self.assertIs(result["evidence_persisted"], False)
        self.assertEqual(result["release_gate"], "HOLD")
        return result["decisions"]

    def test_first_candidate_only_pending_review(self):
        self.assertEqual(self.check([record()])[0]["state"], "pending-review")

    def test_second_batch_same_id_quarantined(self):
        self.check([record()])
        self.assertEqual(self.check([record()])[0]["reason"], "previously-seen-record-id")

    def test_reopened_file_retains_index(self):
        self.check([record()])
        self.assertTrue(self.db.is_file())
        self.assertEqual(self.check([record("r1", "different")])[0]["reason"], "previously-seen-record-id")

    def test_distinct_ids_can_be_indexed(self):
        self.check([record("r1")])
        self.assertEqual(self.check([record("r2")])[0]["state"], "pending-review")

    def test_tampered_candidate_not_indexed(self):
        item = record()
        item["payload"]["content"] = "tampered"
        self.assertEqual(self.check([item])[0]["reason"], "integrity-failure")
        self.assertEqual(self.check([record()])[0]["state"], "pending-review")

    def test_batch_duplicates_both_quarantined_and_not_indexed(self):
        item = record()
        results = self.check([item, copy.deepcopy(item)])
        self.assertEqual([x["state"] for x in results], ["quarantined", "quarantined"])
        self.assertEqual(self.check([record()])[0]["state"], "pending-review")

    def test_database_contains_no_evidence_payload(self):
        self.check([record()])
        with sqlite3.connect(self.db) as conn:
            cols = [item[1] for item in conn.execute("PRAGMA table_info(seen_candidate_ids)")]
            self.assertEqual(cols, ["record_id", "lineage_id", "payload_sha256"])

    def test_malformed_batch_does_not_create_db(self):
        with self.assertRaises(ValueError):
            module.index_candidates(self.db, {"not": "an array"})
        self.assertFalse(self.db.exists())

    def test_database_path_in_memory_is_disallowed(self):
        with self.assertRaises(ValueError):
            module.index_candidates(":memory:", [record()])

    def test_input_unchanged(self):
        items = [record()]
        before = copy.deepcopy(items)
        self.check(items)
        self.assertEqual(items, before)


if __name__ == "__main__":
    unittest.main()
