"""Adversarial tests for the unsigned release boundary."""
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from release_candidate import ROOT,FILES,check,descriptor_digest

DIRECTORY=ROOT/'verification/citadel-a1'
DESCRIPTOR=json.loads((ROOT/'verification/citadel-a2/release-candidate-v0.1.json').read_text())

class ReleaseGate(unittest.TestCase):
    def run_case(self,value=None,root=DIRECTORY,anchor=None,commit=None):
        value=DESCRIPTOR if value is None else value
        return check(json.dumps(value).encode(),root,descriptor_digest(value) if anchor is None else anchor,DESCRIPTOR['source_commit'] if commit is None else commit)

    def test_intact_unsigned_candidate_is_never_authorized(self):
        r=self.run_case();self.assertEqual(r['artifact_integrity'],'VALID');self.assertEqual(r['result'],'INCOMPLETE');self.assertFalse(r['production_release'])

    def test_untrusted_approvals_or_signatures_do_not_authorize(self):
        v=copy.deepcopy(DESCRIPTOR);v['approvals']=['alice','bob'];self.assertEqual(self.run_case(v)['result'],'INVALID')
        v=copy.deepcopy(DESCRIPTOR);v['signature']={'value':'fake','key':'self-declared'};self.assertEqual(self.run_case(v)['result'],'UNKNOWN')

    def test_unknown_version_context_and_anchors(self):
        for field,value,status in [('descriptor_version','9','UNKNOWN'),('world_id','OTHER','CONFLICT'),('source_commit','0'*40,'CONFLICT'),('status','ACTIVE','INVALID')]:
            v=copy.deepcopy(DESCRIPTOR);v[field]=value;self.assertEqual(self.run_case(v)['result'],status)
        self.assertEqual(self.run_case(anchor='')['result'],'INCOMPLETE')
        self.assertEqual(self.run_case(anchor='0'*64)['result'],'CONFLICT')

    def test_inventory_cannot_escape_or_drop_files(self):
        for name in ('../secret','/etc/passwd','C:/secret','expected.json'):
            v=copy.deepcopy(DESCRIPTOR);v['files'][0]['name']=name;self.assertEqual(self.run_case(v)['result'],'INVALID')
        v=copy.deepcopy(DESCRIPTOR);v['files'].pop();self.assertEqual(self.run_case(v)['result'],'INVALID')

    def test_changed_and_missing_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in FILES:(root/name).write_bytes((DIRECTORY/name).read_bytes())
            (root/'bundle.json').write_bytes(b'{}')
            self.assertEqual(self.run_case(root=root)['reason'],'ARTIFACT_DIGEST')
            (root/'bundle.json').unlink()
            self.assertEqual(self.run_case(root=root)['result'],'INVALID')

    def test_policy_requires_two_unassigned_reviewers(self):
        policy=json.loads((ROOT/'specs/citadel-a2/release-policy-v0.1.json').read_text())
        self.assertEqual(policy['required_distinct_reviewers'],2)
        self.assertEqual(policy['designated_reviewers'],[])
        self.assertFalse(policy['production_release_enabled'])
        self.assertEqual(policy['governance_phase'],'INTERIM')
        self.assertEqual(policy['successor_authority'],'AMBASSADORS')
        self.assertTrue(policy['transition_requires_new_policy_version'])

    def test_malformed_descriptors_fail_closed(self):
        for raw in (b'{"a":1,"a":2}',b'\xff',b' '*1048577,b'{"a":1.0}'):
            self.assertEqual(check(raw,DIRECTORY,'0'*64,DESCRIPTOR['source_commit'])['result'],'INVALID')
        for version in (None,[],{},1):
            v=copy.deepcopy(DESCRIPTOR);v['descriptor_version']=version
            self.assertEqual(self.run_case(v)['result'],'INVALID')

    def test_cli_cannot_return_success(self):
        p=subprocess.run([sys.executable,str(ROOT/'tools/citadel_a2/release_candidate.py'),str(ROOT/'verification/citadel-a2/release-candidate-v0.1.json'),str(DIRECTORY),descriptor_digest(DESCRIPTOR),DESCRIPTOR['source_commit']],capture_output=True,check=False)
        self.assertEqual(p.returncode,1)
        self.assertEqual(json.loads(p.stdout)['artifact_integrity'],'VALID')

    def test_linked_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            try:(root/'bundle.json').symlink_to(DIRECTORY/'bundle.json')
            except OSError:self.skipTest('platform does not permit symlink creation')
            self.assertEqual(self.run_case(root=root)['result'],'INVALID')

if __name__=='__main__':unittest.main()
