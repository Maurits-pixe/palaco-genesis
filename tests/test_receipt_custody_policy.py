"""Custody policy cryptographic gate and anti-rollback adversarial tests."""
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

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("custody",ROOT/"tools"/"receipt_custody_policy.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ReceiptCustodyPolicyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db=Path(temp.name)/"receipts.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE observed_handoff_receipts(
                receipt_id TEXT PRIMARY KEY,bundle_sha256 TEXT,recipient_id TEXT,
                custodian_key_id TEXT,receipt_digest TEXT)""")
            mod.anchor.audit._schema(c)
        with sqlite3.connect(self.db) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                      ("1"*32,"b"*64,"custodian-a","c"*64,"d"*64))
            head=mod.anchor.audit.append(c,"1"*32,"b"*64,"custodian-a","c"*64,"d"*64)["head_hash"]
            c.commit()
        self.witness=Ed25519PrivateKey.from_private_bytes(bytes(range(1,33)))
        self.governance=Ed25519PrivateKey.from_private_bytes(bytes(range(11,43)))
        wpub=self.witness.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        gpub=self.governance.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.wid=hashlib.sha256(wpub).hexdigest()
        self.gid=hashlib.sha256(gpub).hexdigest()
        self.wroots={self.wid:wpub}
        self.groots={self.gid:gpub}
        body={"schema_version":"0.1.0","entries":1,"receipt_head_sha256":head}
        signature=self.witness.sign(mod.anchor.DOMAIN+mod.anchor.canonical_anchor(body))
        self.anchored={"anchor":body,"witness_key_id":self.wid,
                       "signature_b64":base64.b64encode(signature).decode()}
        self.signed_policy=self.policy()

    def policy(self, revision=7, minimum=1, witnesses=None):
        body={"schema_version":"0.1.0","revision":revision,"minimum_events":minimum,
              "witness_key_ids":[self.wid] if witnesses is None else witnesses}
        sig=self.governance.sign(mod.DOMAIN+mod.canonical_policy(body))
        return {"policy":body,"issuer_key_id":self.gid,
                "signature_b64":base64.b64encode(sig).decode()}

    def check(self, policy=None, anchor=None, roots=None, wroots=None, revoked=None,
              revoked_witnesses=None, minimum_revision=7, minimum_events=1):
        r=mod.verify(self.db, self.anchored if anchor is None else anchor,
                     self.signed_policy if policy is None else policy,
                     self.groots if roots is None else roots,
                     set() if revoked is None else revoked,
                     self.wroots if wroots is None else wroots,
                     set() if revoked_witnesses is None else revoked_witnesses,
                     minimum_revision,minimum_events)
        self.assertEqual(r["release_gate"],"HOLD")
        self.assertFalse(r["authorization_granted"])
        self.assertFalse(r["automatic_restore"])
        self.assertFalse(r["recovery_approved"])
        return r

    def test_valid_policy_never_authorizes(self):
        self.assertTrue(self.check()["custody_valid"])

    def test_revoked_governance_denied(self):
        self.assertEqual(self.check(revoked={self.gid})["reason"],"governance-revoked")

    def test_untrusted_governance_denied(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-governance")

    def test_revoked_witness_denied(self):
        self.assertEqual(self.check(revoked_witnesses={self.wid})["reason"],"witness-revoked")

    def test_unauthorized_witness_denied(self):
        other="f"*64
        self.assertEqual(self.check(policy=self.policy(witnesses=[other]))["reason"],
                         "witness-not-authorized-by-custody-policy")

    def test_stale_policy_revision_denied(self):
        self.assertEqual(self.check(minimum_revision=8)["reason"],"stale-custody-policy")

    def test_policy_event_floor_denied(self):
        self.assertEqual(self.check(policy=self.policy(minimum=2))["reason"],"stale-receipt-anchor")

    def test_external_event_floor_denied(self):
        self.assertEqual(self.check(minimum_events=2)["reason"],"stale-receipt-anchor")

    def test_changed_policy_signature_denied(self):
        altered=copy.deepcopy(self.signed_policy)
        altered["policy"]["minimum_events"]=2
        self.assertEqual(self.check(policy=altered)["reason"],"invalid-governance-signature")

    def test_forged_governance_signature_denied(self):
        altered=copy.deepcopy(self.signed_policy)
        altered["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(policy=altered)["reason"],"invalid-governance-signature")

    def test_missing_history_denied(self):
        self.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-receipt-db")
        self.assertFalse(self.db.exists())

    def test_changed_local_history_denied(self):
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE observed_handoff_receipts SET receipt_digest=?", ("f"*64,))
        self.assertEqual(self.check()["reason"],"receipt-index-chain-mismatch")

    def test_extra_permission_field_denied(self):
        altered=copy.deepcopy(self.signed_policy)
        altered["policy"]["may_restore"]=True
        self.assertEqual(self.check(policy=altered)["reason"],"invalid-custody-policy-schema")

    def test_no_trusted_revision_denied(self):
        self.assertEqual(self.check(minimum_revision=None)["reason"],"missing-trusted-policy-revision")

    def test_boolean_revision_denied(self):
        altered=copy.deepcopy(self.signed_policy)
        altered["policy"]["revision"]=True
        self.assertEqual(self.check(policy=altered)["reason"],"invalid-custody-policy-revision")


if __name__=="__main__":
    unittest.main()
