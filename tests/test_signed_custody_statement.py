"""Custody statement binding and independent role verification (HOLD)."""
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
spec = importlib.util.spec_from_file_location("custody_statement", ROOT / "tools" / "signed_custody_statement.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SignedCustodyStatementTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "receipts.sqlite"
        with sqlite3.connect(self.db) as conn:
            conn.execute("""CREATE TABLE observed_handoff_receipts(
                receipt_id TEXT PRIMARY KEY, bundle_sha256 TEXT, recipient_id TEXT,
                custodian_key_id TEXT, receipt_digest TEXT)""")
            mod.policy_gate.anchor.audit._schema(conn)
        with sqlite3.connect(self.db) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO observed_handoff_receipts VALUES(?,?,?,?,?)",
                         ("1"*32,"b"*64,"custodian-a","c"*64,"d"*64))
            head = mod.policy_gate.anchor.audit.append(
                conn,"1"*32,"b"*64,"custodian-a","c"*64,"d"*64)["head_hash"]
            conn.commit()
        self.w = Ed25519PrivateKey.from_private_bytes(bytes(range(1,33)))
        self.g = Ed25519PrivateKey.from_private_bytes(bytes(range(11,43)))
        self.c = Ed25519PrivateKey.from_private_bytes(bytes(range(21,53)))
        def keypair(private):
            pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return hashlib.sha256(pub).hexdigest(), pub
        self.wid, wpub = keypair(self.w)
        self.gid, gpub = keypair(self.g)
        self.cid, cpub = keypair(self.c)
        self.wroots, self.groots = {self.wid:wpub}, {self.gid:gpub}
        self.ckeys, self.allow = {self.cid:cpub}, {"custodian-a":{self.cid}}
        anchor_body = {"schema_version":"0.1.0", "entries":1, "receipt_head_sha256":head}
        anchor_sig = self.w.sign(mod.policy_gate.anchor.DOMAIN + mod.policy_gate.anchor.canonical_anchor(anchor_body))
        self.anchor = {"anchor":anchor_body, "witness_key_id":self.wid,
                       "signature_b64":base64.b64encode(anchor_sig).decode()}
        policy_body = {"schema_version":"0.1.0","revision":7,"minimum_events":1,
                       "witness_key_ids":[self.wid]}
        policy_sig = self.g.sign(mod.policy_gate.DOMAIN+mod.policy_gate.canonical_policy(policy_body))
        self.policy = {"policy":policy_body,"issuer_key_id":self.gid,
                       "signature_b64":base64.b64encode(policy_sig).decode()}
        self.statement = self.make_statement()

    def make_statement(self, overrides=None):
        body = {"schema_version":"0.1.0","custodian_id":"custodian-a",
                "statement_id":"1"*32,"disposition":mod.DISPOSITION,
                "policy_envelope_sha256":mod.digest(mod.POLICY_REF_DOMAIN,self.policy),
                "anchor_envelope_sha256":mod.digest(mod.ANCHOR_REF_DOMAIN,self.anchor),
                "policy_revision":7,"receipt_entries":1,
                "receipt_head_sha256":self.anchor["anchor"]["receipt_head_sha256"]}
        body.update(overrides or {})
        sig = self.c.sign(mod.DOMAIN+mod.canonical_statement(body))
        return {"statement":body,"custodian_key_id":self.cid,
                "signature_b64":base64.b64encode(sig).decode()}

    def check(self, stmt=None, allow=None, ckeys=None, revoked=None, policy=None,
              anchor=None, gov=None, wroots=None, floor=1, revision=7, expected="custodian-a"):
        result = mod.verify(
            self.db, self.anchor if anchor is None else anchor,
            self.policy if policy is None else policy,
            self.statement if stmt is None else stmt,
            expected, self.allow if allow is None else allow,
            self.ckeys if ckeys is None else ckeys,
            set() if revoked is None else revoked,
            self.groots if gov is None else gov, set(),
            self.wroots if wroots is None else wroots, set(), revision, floor)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["recovery_approved"])
        self.assertFalse(result["automatic_restore"])
        return result

    def test_valid_signed_claim_pending_only(self):
        self.assertTrue(self.check()["custody_statement_valid"])

    def test_unknown_custodian_identity(self):
        self.assertEqual(self.check(expected="unknown")["reason"],"custodian-identity-mismatch")

    def test_wrong_custodian_key_allowlist(self):
        self.assertEqual(self.check(allow={"custodian-a":set()})["reason"],"custodian-key-not-allowed")

    def test_revoked_custodian(self):
        self.assertEqual(self.check(revoked={self.cid})["reason"],"custodian-revoked")

    def test_invalid_custodian_signature(self):
        e=copy.deepcopy(self.statement)
        e["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(stmt=e)["reason"],"invalid-custodian-signature")

    def test_tampered_policy_binding(self):
        p=copy.deepcopy(self.policy)
        p["policy"]["revision"]=8
        self.assertEqual(self.check(policy=p)["reason"],"custody-statement-envelope-binding-failed")

    def test_tampered_anchor_binding(self):
        a=copy.deepcopy(self.anchor)
        a["anchor"]["entries"]=2
        self.assertEqual(self.check(anchor=a)["reason"],"custody-statement-envelope-binding-failed")

    def test_changed_statement_digest(self):
        e=copy.deepcopy(self.statement)
        e["statement"]["receipt_head_sha256"]="f"*64
        self.assertEqual(self.check(stmt=e)["reason"],"invalid-custodian-signature")

    def test_policy_revision_mismatch(self):
        self.assertEqual(self.check(stmt=self.make_statement({"policy_revision":8}))["reason"],
                         "custody-statement-state-mismatch")

    def test_receipt_count_mismatch(self):
        self.assertEqual(self.check(stmt=self.make_statement({"receipt_entries":2}))["reason"],
                         "custody-statement-state-mismatch")

    def test_stale_governance_floor(self):
        self.assertEqual(self.check(revision=8)["reason"],"stale-custody-policy")

    def test_stale_receipt_floor(self):
        self.assertEqual(self.check(floor=2)["reason"],"stale-receipt-anchor")

    def test_unknown_custodian_public_key(self):
        self.assertEqual(self.check(ckeys={})["reason"],"untrusted-custodian-key")

    def test_extra_approval_field_rejected(self):
        e=copy.deepcopy(self.statement)
        e["statement"]["approved"]=True
        self.assertEqual(self.check(stmt=e)["reason"],"invalid-custody-statement-schema")

    def test_missing_local_database_rejected(self):
        self.db.unlink()
        self.assertEqual(self.check()["reason"],"missing-receipt-db")
        self.assertFalse(self.db.exists())

    def test_custodian_role_collision_denied(self):
        e=self.make_statement()
        e["custodian_key_id"]=self.wid
        self.assertEqual(self.check(stmt=e,allow={"custodian-a":{self.wid}})["reason"],
                         "custodian-role-collision")


if __name__=="__main__":
    unittest.main()
