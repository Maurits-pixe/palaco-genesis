"""Signed registry succession, rotation and fail-closed history tests."""
import base64
import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("succession",ROOT/"tools"/"witness_registry_succession.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class WitnessRegistrySuccessionTests(unittest.TestCase):
    def setUp(self):
        self.issuer=Ed25519PrivateKey.from_private_bytes(bytes(range(31,63)))
        pub=self.issuer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.iid=hashlib.sha256(pub).hexdigest()
        self.roots={self.iid:pub}
        self.a="a"*64
        self.b="b"*64
        self.c="c"*64
        self.snapshots=[
            self.snapshot(1,[(self.a,"org-alpha","active"),(self.b,"org-beta","active")]),
            self.snapshot(2,[(self.a,"org-alpha","revoked"),(self.b,"org-beta","active"),(self.c,"org-alpha","active")])
        ]
        self.records=self.records_for(self.snapshots)

    def snapshot(self,revision,entries):
        body={"schema_version":"0.1.0","revision":revision,"minimum_organizations":2,
              "witnesses":[{"witness_key_id":key,"organization_id":org,"status":status}
                           for key,org,status in sorted(entries)]}
        sig=self.issuer.sign(mod.registry.DOMAIN+mod.registry.canonical_registry(body))
        return {"registry":body,"issuer_key_id":self.iid,"signature_b64":base64.b64encode(sig).decode()}

    def records_for(self,snapshots):
        previous=mod.GENESIS
        records=[]
        for snap in snapshots:
            body={"schema_version":"0.1.0","revision":snap["registry"]["revision"],
                  "registry_envelope_sha256":mod.digest(snap),
                  "previous_record_sha256":previous}
            sig=self.issuer.sign(mod.DOMAIN+mod.canonical_succession(body))
            r={"succession":body,"issuer_key_id":self.iid,"signature_b64":base64.b64encode(sig).decode()}
            records.append(r)
            previous=mod.record_digest(r)
        return records

    def check(self,snapshots=None,records=None,roots=None,revoked=None,
              genesis=None,head=None,floor=2):
        ss=self.snapshots if snapshots is None else snapshots
        rr=self.records if records is None else records
        result=mod.verify(ss,rr,self.roots if roots is None else roots,
                          set() if revoked is None else revoked,
                          mod.digest(self.snapshots[0]) if genesis is None else genesis,
                          mod.record_digest(self.records[-1]) if head is None else head,floor)
        self.assertEqual(result["release_gate"],"HOLD")
        self.assertFalse(result["authorization_granted"])
        self.assertFalse(result["automatic_restore"])
        self.assertFalse(result["recovery_approved"])
        return result

    def test_valid_signed_rotation_pending_only(self):
        self.assertTrue(self.check()["succession_valid"])

    def test_untrusted_issuer(self):
        self.assertEqual(self.check(roots={})["reason"],"untrusted-registry-issuer")

    def test_revoked_issuer(self):
        self.assertEqual(self.check(revoked={self.iid})["reason"],"registry-issuer-revoked")

    def test_malformed_genesis_pin(self):
        self.assertEqual(self.check(genesis="wrong")["reason"],"missing-independent-history-anchor")

    def test_wrong_genesis_pin(self):
        self.assertEqual(self.check(genesis="f"*64)["reason"],"untrusted-history-genesis")

    def test_wrong_external_head(self):
        self.assertEqual(self.check(head="f"*64)["reason"],"registry-history-head-mismatch")

    def test_history_floor_rollback(self):
        self.assertEqual(self.check(floor=3)["reason"],"registry-history-rollback")

    def test_missing_latest_revision(self):
        self.assertEqual(self.check(snapshots=self.snapshots[:1],records=self.records[:1])["reason"],
                         "registry-history-rollback")

    def test_deleted_middle_revision(self):
        third=self.snapshot(3,[(self.a,"org-alpha","revoked"),(self.b,"org-beta","active"),
                               (self.c,"org-alpha","active")])
        ss=[self.snapshots[0],third]
        rr=self.records_for(ss)
        self.assertEqual(self.check(snapshots=ss,records=rr)["reason"],"missing-intermediate-revision")

    def test_tampered_succession_signature(self):
        rr=copy.deepcopy(self.records)
        rr[-1]["signature_b64"]=base64.b64encode(bytes(64)).decode()
        self.assertEqual(self.check(records=rr)["reason"],"invalid-succession-signature")

    def test_tampered_registry_signature(self):
        ss=copy.deepcopy(self.snapshots)
        ss[-1]["registry"]["witnesses"][0]["organization_id"]="org-gamma"
        self.assertEqual(self.check(snapshots=ss)["reason"],"invalid-registry-signature")

    def test_link_mismatch_even_with_new_signature(self):
        rr=copy.deepcopy(self.records)
        rr[-1]["succession"]["previous_record_sha256"]="f"*64
        rr[-1]["signature_b64"]=base64.b64encode(
            self.issuer.sign(mod.DOMAIN+mod.canonical_succession(rr[-1]["succession"]))).decode()
        self.assertEqual(self.check(records=rr)["reason"],"succession-link-mismatch")

    def test_missing_key_history_rejected(self):
        ss=[self.snapshots[0],self.snapshot(2,[(self.b,"org-beta","active"),
            (self.c,"org-alpha","active")])]
        self.assertEqual(self.check(snapshots=ss,records=self.records_for(ss),
                         head=mod.record_digest(self.records_for(ss)[-1]))["reason"],
                         "witness-key-history-rewritten")

    def test_revoked_key_resurrection_rejected(self):
        ss=self.snapshots+[self.snapshot(3,[(self.a,"org-alpha","active"),
            (self.b,"org-beta","active"),(self.c,"org-alpha","revoked")])]
        rr=self.records_for(ss)
        self.assertEqual(self.check(snapshots=ss,records=rr,head=mod.record_digest(rr[-1]))["reason"],
                         "revoked-key-resurrected")

    def test_reassignment_rejected(self):
        ss=[self.snapshots[0],self.snapshot(2,[(self.a,"org-gamma","active"),
            (self.b,"org-beta","active")])]
        rr=self.records_for(ss)
        self.assertEqual(self.check(snapshots=ss,records=rr,head=mod.record_digest(rr[-1]))["reason"],
                         "witness-key-history-rewritten")

    def test_duplicate_revisions_rejected(self):
        ss=[self.snapshots[0],self.snapshots[0]]
        rr=self.records_for(ss)
        self.assertEqual(self.check(snapshots=ss,records=rr,head=mod.record_digest(rr[-1]))["reason"],
                         "missing-intermediate-revision")

    def test_missing_history_rejected(self):
        self.assertEqual(self.check(snapshots=[],records=[])["reason"],"invalid-history-length")

    def test_extra_permission_rejected(self):
        rr=copy.deepcopy(self.records)
        rr[0]["authorization"]=True
        self.assertEqual(self.check(records=rr)["reason"],"invalid-succession-envelope")


if __name__=="__main__":
    unittest.main()
