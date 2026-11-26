"""Fail-closed tests for local evidence intake. No network or writes."""
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("local_intake", ROOT / "tools" / "local_evidence_intake.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def record(record_id="rec-1", payload=None):
    if payload is None:
        payload = {"content": "untrusted evidence"}
    digest = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")).hexdigest()
    return {"schema_version": "0.1.0", "record_id": record_id, "lineage_id": "lineage-1",
            "payload": payload, "payload_sha256": digest}


class EvidenceIntakeTests(unittest.TestCase):
    def decision(self, candidate):
        report = engine.inspect(candidate)
        self.assertEqual(report["release_gate"], "HOLD")
        self.assertIs(report["authorization_granted"], False)
        self.assertIs(report["persisted"], False)
        return report["decisions"]

    def test_intact_remains_untrusted(self):
        self.assertEqual(self.decision([record()])[0]["state"], "pending-review")

    def test_tampering_quarantined(self):
        item = record()
        item["payload"]["content"] = "tampered"
        self.assertEqual(self.decision([item])[0]["reason"], "integrity-failure")

    def test_identical_duplicates_quarantined(self):
        item = record()
        result = self.decision([item, copy.deepcopy(item)])
        self.assertEqual([r["reason"] for r in result], ["duplicate-record-id"] * 2)

    def test_conflicting_duplicates_quarantined(self):
        result = self.decision([record(), record(payload={"content": "other"})])
        self.assertEqual([r["reason"] for r in result], ["duplicate-record-id"] * 2)

    def test_missing_lineage_quarantined(self):
        item = record()
        item["lineage_id"] = ""
        self.assertEqual(self.decision([item])[0]["reason"], "missing-provenance")

    def test_unsupported_schema_quarantined(self):
        item = record()
        item["schema_version"] = "2.0.0"
        self.assertEqual(self.decision([item])[0]["reason"], "unsupported-schema")

    def test_extra_authority_field_rejected(self):
        item = record()
        item["owner"] = True
        self.assertEqual(self.decision([item])[0]["reason"], "unsupported-schema")

    def test_nonfinite_payload_quarantined(self):
        item = record()
        item["payload"] = {"x": float("nan")}
        self.assertEqual(self.decision([item])[0]["reason"], "malformed-payload")

    def test_invalid_record_quarantined(self):
        self.assertEqual(self.decision([None])[0]["reason"], "malformed-record")

    def test_large_batch_rejected(self):
        with self.assertRaises(ValueError):
            engine.inspect([None] * (engine.MAX_RECORDS + 1))

    def test_independent_records_preserve_order(self):
        decisions = self.decision([record("rec-2"), record("rec-1")])
        self.assertEqual([d["record_id"] for d in decisions], ["rec-2", "rec-1"])
        self.assertTrue(all(d["state"] == "pending-review" for d in decisions))

    def test_replay_across_batches_quarantined(self):
        report = engine.inspect([record()], ["rec-1"])
        self.assertEqual(report["decisions"][0]["reason"], "previously-seen-record-id")
        self.assertFalse(report["authorization_granted"])

    def test_seen_ids_do_not_block_other_records(self):
        report = engine.inspect([record("rec-2")], ["rec-1"])
        self.assertEqual(report["decisions"][0]["state"], "pending-review")

    def test_invalid_seen_ids_fail_closed(self):
        with self.assertRaises(ValueError):
            engine.inspect([record()], [{"rec": "bad"}])

    def test_seen_ids_limit(self):
        with self.assertRaises(ValueError):
            engine.inspect([record()], ["x"] * (engine.MAX_RECORDS + 1))

    def test_seen_input_unchanged(self):
        seen = ["rec-1"]
        engine.inspect([record()], seen)
        self.assertEqual(seen, ["rec-1"])

    def test_input_not_mutated(self):
        items = [record()]
        before = copy.deepcopy(items)
        self.decision(items)
        self.assertEqual(items, before)


if __name__ == "__main__":
    unittest.main()
