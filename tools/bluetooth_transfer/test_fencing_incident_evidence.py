"""Read-only fencing incident evidence tests, using untrusted synthetic stores."""
from dataclasses import replace
import json
import unittest

from anchored_challenges import EMPTY_ROOT
from native_checkpoint_scope import NativeCheckpoint
from native_fencing_gate import FencedSnapshot
from witnessed_sqlite_fencing import FencingWitnessState
from fencing_incident_evidence import (
    FencingIncidentEvidence, inspect_fencing_incident,
    verify_fencing_incident_evidence, DOMAIN,
)

NS = b"e" * 32
ROOT = "a" * 64


class FakeRead:
    def __init__(self, value):
        self.value = value
        self.reads = 0
        self.fail = False
        self.next = None

    def read(self):
        self.reads += 1
        if self.fail:
            raise OSError("secret service path must not leak")
        if self.next is not None and self.reads > 1:
            return self.next
        return self.value


class FencingIncidentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.sqlite = FakeRead(FencedSnapshot(
            NS, 1, False, NativeCheckpoint(NS, 0, EMPTY_ROOT),
        ))
        self.witness = FakeRead(FencingWitnessState(
            NS, 0, 1, False, 0, EMPTY_ROOT,
        ))

    def report(self):
        return inspect_fencing_incident(self.sqlite, self.witness, NS)

    def test_match_remains_hold_and_deny(self):
        record = self.report()
        data = json.loads(record.canonical_json)
        self.assertEqual(data["status"], "match")
        self.assertEqual((data["decision"], data["authorization"]), ("HOLD", "DENY"))
        self.assertTrue(verify_fencing_incident_evidence(record))

    def test_split_commit_checkpoint_report(self):
        self.witness.value = FencingWitnessState(NS, 1, 1, False, 1, ROOT)
        data = json.loads(self.report().canonical_json)
        self.assertEqual(data["status"], "mismatch")
        self.assertEqual(data["sqlite"]["count"], 0)
        self.assertEqual(data["witness"]["count"], 1)

    def test_split_commit_hold_report(self):
        self.witness.value = FencingWitnessState(NS, 1, 2, True, 0, EMPTY_ROOT)
        data = json.loads(self.report().canonical_json)
        self.assertEqual(data["status"], "mismatch")
        self.assertTrue(data["witness"]["held"])

    def test_same_count_content_mismatch(self):
        self.sqlite.value = FencedSnapshot(
            NS, 1, False, NativeCheckpoint(NS, 1, ROOT),
        )
        self.witness.value = FencingWitnessState(NS, 1, 1, False, 1, EMPTY_ROOT)
        self.assertEqual(json.loads(self.report().canonical_json)["status"], "mismatch")

    def test_witness_outage_yields_unavailable(self):
        self.witness.fail = True
        data = json.loads(self.report().canonical_json)
        self.assertEqual(data["status"], "unavailable")
        self.assertNotIn("secret service path", json.dumps(data))

    def test_sqlite_outage_yields_unavailable(self):
        self.sqlite.fail = True
        self.assertEqual(json.loads(self.report().canonical_json)["status"], "unavailable")

    def test_concurrent_sqlite_change_reported(self):
        self.sqlite.next = replace(
            self.sqlite.value, checkpoint=NativeCheckpoint(NS, 1, ROOT),
        )
        self.assertEqual(json.loads(self.report().canonical_json)["status"],
                         "changed_during_read")

    def test_concurrent_witness_change_reported(self):
        self.witness.next = replace(self.witness.value, revision=1)
        self.assertEqual(json.loads(self.report().canonical_json)["status"],
                         "changed_during_read")

    def test_reports_are_deterministic(self):
        self.assertEqual(self.report(), self.report())

    def test_evidence_tampering_detected(self):
        report = self.report()
        changed = FencingIncidentEvidence(
            report.canonical_json.replace('"HOLD"', '"ALLOW"'), report.sha256,
        )
        self.assertFalse(verify_fencing_incident_evidence(changed))

    def test_fake_hash_not_signature(self):
        report = self.report()
        import hashlib
        self.assertEqual(report.sha256, hashlib.sha256(
            DOMAIN + report.canonical_json.encode("ascii")
        ).hexdigest())

    def test_extra_fields_denied(self):
        report = self.report()
        doc = json.loads(report.canonical_json)
        doc["authorized"] = True
        self.assertFalse(verify_fencing_incident_evidence(
            FencingIncidentEvidence(json.dumps(doc), report.sha256),
        ))

    def test_no_mutation_methods_invoked(self):
        self.report()
        self.assertEqual(self.sqlite.reads, 2)
        self.assertEqual(self.witness.reads, 2)

    def test_foreign_namespace_unavailable(self):
        self.sqlite.value = FencedSnapshot(
            b"f" * 32, 1, False, NativeCheckpoint(b"f" * 32, 0, EMPTY_ROOT),
        )
        self.assertEqual(json.loads(self.report().canonical_json)["status"], "unavailable")

    def test_invalid_evidence_type(self):
        self.assertFalse(verify_fencing_incident_evidence("forged"))

    def test_missing_payload_field_denied(self):
        report = self.report()
        doc = json.loads(report.canonical_json)
        del doc["status"]
        self.assertFalse(verify_fencing_incident_evidence(
            FencingIncidentEvidence(json.dumps(doc), report.sha256),
        ))


if __name__ == "__main__":
    unittest.main()
