"""Two-person approval gate tests; private test keys exist in memory only."""
import copy
import json
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from release_candidate import ROOT, descriptor_digest
from verify_approvals import PROFILE, policy_digest, approval_message, release_digest, verify_approvals

DESCRIPTOR_RAW=(ROOT/'verification/citadel-a2/release-candidate-v0.1.json').read_bytes()
DESCRIPTOR=json.loads(DESCRIPTOR_RAW)
DIRECTORY=ROOT/'verification/citadel-a1'

class Approvals(unittest.TestCase):
    def setUp(self):
        self.keys={name:Ed25519PrivateKey.generate() for name in ('test:alice','test:bob')}
        self.policy=dict(policy_version='0.2',signature_profile=PROFILE,governance_phase='INTERIM',required_distinct_reviewers=2,citadel_id=DESCRIPTOR['citadel_id'],world_id=DESCRIPTOR['world_id'],reviewers=[dict(reviewer_id=name,key_id=name+':key1',public_key_hex=key.public_key().public_bytes_raw().hex(),status='ACTIVE') for name,key in self.keys.items()])
        self.envelope=dict(signature_profile=PROFILE,policy_digest=policy_digest(self.policy),descriptor_digest=descriptor_digest(DESCRIPTOR),source_commit=DESCRIPTOR['source_commit'],citadel_id=DESCRIPTOR['citadel_id'],world_id=DESCRIPTOR['world_id'],release_sequence=1,previous_release_digest=None,approvals=[])
        self.sign()

    def sign(self):
        self.envelope['policy_digest']=policy_digest(self.policy)
        self.envelope['approvals']=[dict(reviewer_id=name,key_id=name+':key1',signature_hex=key.sign(approval_message(self.envelope,name,name+':key1')).hex()) for name,key in self.keys.items()]

    def check(self,**kw):
        args=dict(envelope_raw=json.dumps(self.envelope).encode(),policy_raw=json.dumps(self.policy).encode(),descriptor_raw=DESCRIPTOR_RAW,artifact_directory=DIRECTORY,expected_policy_digest=policy_digest(self.policy),expected_descriptor_digest=descriptor_digest(DESCRIPTOR),expected_commit=DESCRIPTOR['source_commit'],last_sequence=0,previous_release_digest=None)
        args.update(kw)
        return verify_approvals(**args)

    def test_two_distinct_signatures(self):
        r=self.check();self.assertEqual(r['result'],'VALID');self.assertFalse(r['production_release']);self.assertEqual(r['release_digest'],release_digest(self.envelope))

    def test_one_or_no_approval(self):
        self.envelope['approvals'].pop();self.assertEqual(self.check()['reason'],'REQUIRED_APPROVALS_MISSING')
        self.envelope['approvals']=[];self.assertEqual(self.check()['result'],'INCOMPLETE')

    def test_same_person_twice(self):
        self.envelope['approvals'][1]=copy.deepcopy(self.envelope['approvals'][0])
        self.assertEqual(self.check()['reason'],'DUPLICATE_REVIEWER_APPROVAL')

    def test_same_key_two_person_labels(self):
        self.policy['reviewers'][1]['public_key_hex']=self.policy['reviewers'][0]['public_key_hex'];self.sign()
        self.assertEqual(self.check()['reason'],'REVIEWERS_AND_KEYS_MUST_BE_DISTINCT')

    def test_duplicate_reviewer_policy(self):
        self.policy['reviewers'][1]['reviewer_id']=self.policy['reviewers'][0]['reviewer_id'];self.sign()
        self.assertEqual(self.check()['result'],'INVALID')

    def test_key_revocation(self):
        self.policy['reviewers'][0]['status']='REVOKED';self.sign()
        self.assertEqual(self.check()['reason'],'REVIEWER_KEY_REVOKED')

    def test_wrong_key_or_signature(self):
        self.envelope['approvals'][0]['signature_hex']='00'*64
        self.assertEqual(self.check()['reason'],'INVALID_APPROVAL_SIGNATURE')
        self.sign();self.envelope['approvals'][0]['key_id']='other:key'
        self.assertEqual(self.check()['reason'],'UNTRUSTED_REVIEWER_KEY')

    def test_swapped_signature_is_not_approval(self):
        self.envelope['approvals'][0]['signature_hex']=self.envelope['approvals'][1]['signature_hex']
        self.assertEqual(self.check()['reason'],'INVALID_APPROVAL_SIGNATURE')

    def test_anchor_substitution(self):
        for field,value in [('policy_digest','0'*64),('descriptor_digest','0'*64),('source_commit','0'*40),('world_id','OTHER')]:
            original=self.envelope[field];self.envelope[field]=value
            self.assertEqual(self.check()['result'],'CONFLICT');self.envelope[field]=original
        self.assertEqual(self.check(expected_policy_digest='')['result'],'INCOMPLETE')

    def test_replay_rollback_and_gap(self):
        self.assertEqual(self.check(last_sequence=1,previous_release_digest='0'*64)['reason'],'RELEASE_ROLLBACK_OR_REPLAY')
        self.envelope['release_sequence']=3;self.sign();self.assertEqual(self.check()['reason'],'RELEASE_SEQUENCE_GAP')

    def test_previous_release_context_is_signed(self):
        self.envelope['release_sequence']=2;self.envelope['previous_release_digest']='a'*64;self.sign()
        self.assertEqual(self.check(last_sequence=1,previous_release_digest='a'*64)['result'],'VALID')
        self.assertEqual(self.check(last_sequence=1,previous_release_digest='b'*64)['reason'],'PREVIOUS_RELEASE_CONFLICT')
        self.envelope['previous_release_digest']='b'*64
        self.assertEqual(self.check(last_sequence=1,previous_release_digest='b'*64)['reason'],'INVALID_APPROVAL_SIGNATURE')

    def test_policy_handover_not_silent(self):
        self.policy['governance_phase']='AMBASSADORS';self.sign()
        self.assertEqual(self.check()['reason'],'GOVERNANCE_HANDOVER_NOT_IMPLEMENTED')

    def test_unknown_profile_and_threshold(self):
        self.envelope['signature_profile']='future';self.assertEqual(self.check()['result'],'UNKNOWN')
        self.envelope['signature_profile']=PROFILE;self.policy['required_distinct_reviewers']=0;self.sign()
        self.assertEqual(self.check()['reason'],'UNSUPPORTED_INTERIM_THRESHOLD')

    def test_pending_designations(self):
        self.policy['reviewers']=[];self.sign()
        self.assertEqual(self.check()['reason'],'REQUIRED_REVIEWERS_NOT_DESIGNATED')

    def test_explicit_single_reviewer_policy(self):
        self.policy['required_distinct_reviewers']=1
        self.policy['reviewers']=self.policy['reviewers'][:1]
        del self.keys['test:bob'];self.sign()
        self.assertEqual(self.check()['result'],'VALID')
        self.envelope['approvals']=[];self.assertEqual(self.check()['result'],'INCOMPLETE')

    def test_threshold_cannot_be_downgraded_without_trusted_policy_change(self):
        original_anchor=policy_digest(self.policy)
        self.policy['required_distinct_reviewers']=1
        self.policy['reviewers']=self.policy['reviewers'][:1]
        del self.keys['test:bob'];self.sign()
        self.assertEqual(self.check(expected_policy_digest=original_anchor)['reason'],'POLICY_ANCHOR_CONFLICT')

    def test_malformed_material(self):
        for raw in (b'[]',b'{"a":1,"a":2}',b' '*1048577,b'\xff'):
            self.assertEqual(self.check(envelope_raw=raw)['result'],'INVALID')
        for value in (True,0,'1',None):
            self.envelope['release_sequence']=value;self.assertEqual(self.check()['result'],'INVALID')

    def test_changed_artifact_material(self):
        self.assertNotEqual(self.check(descriptor_raw=b'{}')['result'],'VALID')

    def test_approval_order_is_fixed(self):
        self.envelope['approvals'].reverse();self.assertEqual(self.check()['reason'],'APPROVAL_ORDER')

    def test_missing_or_extra_fields(self):
        self.envelope['self_approved']=True;self.assertEqual(self.check()['result'],'INVALID')
        del self.envelope['self_approved'];del self.envelope['source_commit'];self.assertEqual(self.check()['result'],'INVALID')

if __name__=='__main__':unittest.main()
