"""Synthetic proof bundle tests: never treat fixtures as real authority."""
import hashlib
import json
import unittest

from offline_stage import _canonical
from recovery_governance_v12 import GENESIS, proposal, record_review
from governance_proof_bundle_v14 import (
    ProofBundleError, make_bundle, verify_bundle
)


class ProofBundleTests(unittest.TestCase):
    def setUp(self):
        self.backup = b"synthetic-backup"
        self.evidence = b"synthetic-evidence"
        self.plan = proposal(
            self.backup, destination_name="new-policy.sqlite",
            sequence=1, head="a"*64,
            evidence_sha256=hashlib.sha256(self.evidence).hexdigest())
        first, head = record_review(
            (), plan=self.plan, expected_head=GENESIS,
            actor_id="owner-fixture", role="owner",
            verdict="approve-candidate", receipt="owner-receipt")
        second, head = record_review(
            (first,), plan=self.plan, expected_head=head,
            actor_id="reviewer-fixture", role="independent-reviewer",
            verdict="approve-candidate", receipt="reviewer-receipt")
        self.reviews = [first, second]
        self.head = head
        self.bundle = make_bundle(
            self.plan, self.reviews, backup_bytes=self.backup,
            evidence_bytes=self.evidence)

    def verify(self, *, bundle=None, backup=None, evidence=None,
               verify_role=None, get_trusted_audit_anchor=None):
        return verify_bundle(
            self.bundle if bundle is None else bundle,
            backup_bytes=self.backup if backup is None else backup,
            evidence_bytes=self.evidence if evidence is None else evidence,
            verify_role=(lambda *_: True) if verify_role is None else verify_role,
            get_trusted_audit_anchor=(
                lambda _: (2, self.head)
            ) if get_trusted_audit_anchor is None else get_trusted_audit_anchor)

    def test_fixture_positive_never_authorizes(self):
        report = self.verify()
        self.assertIs(report["candidate_review_complete"], True)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_canonical_export_roundtrip(self):
        self.assertEqual(_canonical(json.loads(self.bundle)), self.bundle)

    def test_modified_backup_denied(self):
        with self.assertRaises(ProofBundleError):
            self.verify(backup=self.backup+b"x")

    def test_modified_evidence_denied(self):
        with self.assertRaises(ProofBundleError):
            self.verify(evidence=self.evidence+b"x")

    def test_bad_review_head_denied(self):
        value = json.loads(self.bundle)
        value["review_head"] = "0"*64
        with self.assertRaisesRegex(ProofBundleError, "REVIEW_HEAD_MISMATCH"):
            self.verify(bundle=_canonical(value))

    def test_reordered_review_denied(self):
        value = json.loads(self.bundle)
        value["reviews"].reverse()
        with self.assertRaises(ProofBundleError):
            self.verify(bundle=_canonical(value))

    def test_modified_receipt_denied_without_external_trust(self):
        value = json.loads(self.bundle)
        value["reviews"][0]["receipt"] = "changed"
        with self.assertRaises(ProofBundleError):
            self.verify(bundle=_canonical(value))

    def test_unknown_bundle_field_denied(self):
        value = json.loads(self.bundle)
        value["authorize"] = True
        with self.assertRaisesRegex(ProofBundleError, "INVALID_BUNDLE_SCHEMA"):
            self.verify(bundle=_canonical(value))

    def test_missing_review_field_denied(self):
        value = json.loads(self.bundle)
        del value["reviews"][0]["role"]
        with self.assertRaises(ProofBundleError):
            self.verify(bundle=_canonical(value))

    def test_noncanonical_bytes_denied(self):
        with self.assertRaisesRegex(ProofBundleError, "NONCANONICAL_BUNDLE"):
            self.verify(bundle=self.bundle+b" ")

    def test_wrong_review_count_denied(self):
        value = json.loads(self.bundle)
        value["review_count"] = 5
        with self.assertRaisesRegex(ProofBundleError, "REVIEW_HEAD_MISMATCH"):
            self.verify(bundle=_canonical(value))

    def test_boolean_review_count_denied(self):
        value = json.loads(self.bundle)
        value["review_count"] = True
        with self.assertRaisesRegex(ProofBundleError, "REVIEW_HEAD_MISMATCH"):
            self.verify(bundle=_canonical(value))

    def test_stale_anchor_denied(self):
        with self.assertRaises(ProofBundleError):
            self.verify(get_trusted_audit_anchor=lambda _: (0, GENESIS))

    def test_false_role_denied(self):
        with self.assertRaises(ProofBundleError):
            self.verify(verify_role=lambda *_: False)

    def test_truthy_role_denied(self):
        with self.assertRaises(ProofBundleError):
            self.verify(verify_role=lambda *_: 1)

    def test_missing_anchor_denied(self):
        with self.assertRaises(ProofBundleError):
            verify_bundle(self.bundle, backup_bytes=self.backup,
                          evidence_bytes=self.evidence,
                          verify_role=lambda *_: True,
                          get_trusted_audit_anchor=None)

    def test_missing_role_verifier_denied(self):
        with self.assertRaises(ProofBundleError):
            verify_bundle(self.bundle, backup_bytes=self.backup,
                          evidence_bytes=self.evidence,
                          verify_role=None,
                          get_trusted_audit_anchor=lambda _: (2, self.head))

    def test_reject_veto_not_complete(self):
        first = self.reviews[0]
        second, new_head = record_review(
            (first,), plan=self.plan, expected_head=self.reviews[1]["previous"],
            actor_id="reviewer-fixture", role="independent-reviewer",
            verdict="reject", receipt="reviewer-receipt")
        bundle = make_bundle(self.plan, [first, second],
                             backup_bytes=self.backup, evidence_bytes=self.evidence)
        report = self.verify(
            bundle=bundle, get_trusted_audit_anchor=lambda _: (2, new_head))
        self.assertIs(report["candidate_review_complete"], False)

    def test_report_does_not_leak_receipts(self):
        output = str(self.verify())
        self.assertNotIn("owner-receipt", output)
        self.assertNotIn("reviewer-receipt", output)

    def test_empty_reviews_denied(self):
        with self.assertRaises(ProofBundleError):
            make_bundle(self.plan, [], backup_bytes=self.backup,
                        evidence_bytes=self.evidence)


if __name__ == "__main__":
    unittest.main()
