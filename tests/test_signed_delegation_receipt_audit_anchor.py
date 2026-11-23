"""Detached multi-witness receipt audit anchor: adversarial regressions."""
import base64
import copy
import hashlib
import importlib.util
import sqlite3
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
_fixture_spec = importlib.util.spec_from_file_location(
    "receipt_audit_fixture",
    ROOT / "tests" / "test_delegation_receipt_audit_chain.py")
fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(fixture)
_spec = importlib.util.spec_from_file_location(
    "signed_receipt_audit", ROOT / "tools" / "signed_delegation_receipt_audit_anchor.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class SignedDelegationReceiptAuditAnchorTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.DelegationReceiptAuditTests(
            methodName="test_first_receipt_is_chained")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.recorded = self.f.f.record()
        self.signers = [
            Ed25519PrivateKey.from_private_bytes(bytes(range(21, 53))),
            Ed25519PrivateKey.from_private_bytes(bytes(range(51, 83)))
        ]  # TEST ONLY: not issued or held by real witnesses.
        self.roots = {}
        self.orgs = {}
        self.ids = []
        for signer, organization in zip(self.signers, ("archive-witness-a", "archive-witness-b")):
            pub = signer.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key = hashlib.sha256(pub).hexdigest()
            self.ids.append(key)
            self.roots[key] = pub
            self.orgs[key] = organization
        self.envelopes = [self.envelope(0), self.envelope(1)]

    def envelope(self, index, overrides=None):
        body = {"schema_version": "0.1.0", "entries": 1,
                "audit_head_sha256": self.recorded["head_hash"]}
        body.update(overrides or {})
        signature = self.signers[index].sign(mod.DOMAIN + mod.canonical(body))
        return {"checkpoint": body, "witness_key_id": self.ids[index],
                "signature_b64": base64.b64encode(signature).decode()}

    def check(self, envelopes=None, roots=None, orgs=None, revoked=None,
              required=2, head=None, minimum=1):
        result = mod.verify(
            self.f.f.db, self.envelopes if envelopes is None else envelopes,
            self.roots if roots is None else roots,
            self.orgs if orgs is None else orgs,
            set() if revoked is None else revoked,
            required, self.recorded["head_hash"] if head is None else head, minimum)
        self.assertEqual(result["release_gate"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_two_independent_witnesses_pending_only(self):
        value = self.check()
        self.assertTrue(value["witnessed_audit_valid"])
        self.assertEqual(value["organizations"], 2)
        self.assertEqual(value["entries"], 1)

    def test_witness_order_independent(self):
        self.assertTrue(self.check(list(reversed(self.envelopes)))["witnessed_audit_valid"])

    def test_one_witness_insufficient(self):
        self.assertEqual(self.check([self.envelopes[0]])["reason"], "invalid-witness-count")

    def test_duplicate_witness_denied(self):
        self.assertEqual(self.check([self.envelopes[0], self.envelopes[0]])["reason"],
                         "duplicate-receipt-witness")

    def test_two_keys_one_organization_denied(self):
        policy = {key: "archive-witness-a" for key in self.ids}
        self.assertEqual(self.check(orgs=policy)["reason"], "insufficient-eligible-organizations")

    def test_revoked_witness_denied(self):
        self.assertEqual(self.check(revoked={self.ids[1]})["reason"],
                         "insufficient-eligible-organizations")

    def test_unknown_witness_denied(self):
        policy = {self.ids[0]: "archive-witness-a", "f"*64: "archive-witness-b"}
        self.assertEqual(self.check(orgs=policy)["reason"], "receipt-witness-not-allowed")

    def test_untrusted_second_key_denied(self):
        roots = {self.ids[0]: self.roots[self.ids[0]]}
        self.assertEqual(self.check(roots=roots)["reason"], "untrusted-receipt-witness")

    def test_tampered_second_signature_denied(self):
        envelopes = copy.deepcopy(self.envelopes)
        envelopes[1]["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(envelopes)["reason"], "invalid-receipt-witness-signature")

    def test_invalid_second_signature_encoding_denied(self):
        envelopes = copy.deepcopy(self.envelopes)
        envelopes[1]["signature_b64"] = "!"
        self.assertEqual(self.check(envelopes)["reason"],
                         "invalid-receipt-witness-signature-format")

    def test_valid_but_conflicting_head_denied(self):
        conflict = self.envelope(1, {"audit_head_sha256": "f"*64})
        self.assertEqual(self.check([self.envelopes[0], conflict])["reason"],
                         "conflicting-receipt-audit-checkpoint")

    def test_valid_but_conflicting_count_denied(self):
        conflict = self.envelope(1, {"entries": 2})
        self.assertEqual(self.check([self.envelopes[0], conflict])["reason"],
                         "conflicting-receipt-audit-checkpoint")

    def test_changed_unsigned_head_denied(self):
        changed = copy.deepcopy(self.envelopes)
        changed[1]["checkpoint"]["audit_head_sha256"] = "f"*64
        self.assertEqual(self.check(changed)["reason"], "invalid-receipt-witness-signature")

    def test_added_authority_field_denied(self):
        changed = copy.deepcopy(self.envelopes)
        changed[0]["checkpoint"]["authorization_granted"] = True
        self.assertEqual(self.check(changed)["reason"], "invalid-receipt-checkpoint-schema")

    def test_boolean_count_denied(self):
        changed = copy.deepcopy(self.envelopes)
        changed[0]["checkpoint"]["entries"] = True
        self.assertEqual(self.check(changed)["reason"], "invalid-receipt-checkpoint-count")

    def test_wrong_external_pin_denied(self):
        self.assertEqual(self.check(head="f"*64)["reason"], "receipt-audit-head-mismatch")

    def test_external_floor_above_count_denied(self):
        self.assertEqual(self.check(minimum=2)["reason"], "receipt-audit-rollback")

    def test_missing_external_head_denied(self):
        result = mod.verify(self.f.f.db, self.envelopes, self.roots,
                            self.orgs, set(), 2, None, 1)
        self.assertEqual(result["reason"], "missing-independent-receipt-audit-anchor")

    def test_invalid_boolean_quorum_denied(self):
        self.assertEqual(self.check(required=True)["reason"], "missing-independent-witness-policy")

    def test_invalid_organization_id_denied(self):
        policy = dict(self.orgs)
        policy[self.ids[1]] = "../invalid"
        self.assertEqual(self.check(orgs=policy)["reason"],
                         "invalid-witness-organization-policy")

    def test_tampered_local_receipt_denied(self):
        with sqlite3.connect(self.f.f.db) as conn:
            conn.execute("UPDATE delegation_handoff_receipts SET receipt_sha256=?", ("f"*64,))
        self.assertEqual(self.check()["reason"], "receipt-audit-integrity-failed")

    def test_deleted_local_history_denied(self):
        self.f.f.db.unlink()
        self.assertEqual(self.check()["reason"], "missing-receipt-register")

    def test_witness_key_cannot_equal_recipient_signing_key(self):
        key = self.f.f.rid
        pub = self.f.f.roots[key]
        policy = {self.ids[0]: "archive-witness-a", key: "archive-witness-b"}
        roots = dict(self.roots)
        roots[key] = pub
        tampered = copy.deepcopy(self.envelopes[1])
        tampered["witness_key_id"] = key
        self.assertEqual(self.check([self.envelopes[0], tampered],
                                    roots=roots, orgs=policy)["reason"],
                         "receipt-signer-witness-role-collision")


if __name__ == "__main__":
    unittest.main()
