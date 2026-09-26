import copy
import unittest
from registry import *

NOW='2026-09-26T14:00:00Z'
SOURCE='a'*64
POLICY='b'*64

def request(state,target='REVIEWABLE',**updates):
    r=dict(schema_version=PROFILE,request_id=f'test-{state.sequence+1}',release_id=state.release_id,source_version=SOURCE,policy_digest=POLICY,citadel_id=state.citadel_id,world_id=state.world_id,target=target,sequence=state.sequence+1,previous_digest=state.head,issued_at=NOW,expires_at='2026-09-26T14:05:00Z')
    r.update(updates);return r

class RegistryTests(unittest.TestCase):
    def setUp(self): self.initial=Release('test-only',SOURCE,POLICY)
    def advance(self,s,target='REVIEWABLE',**kw):
        return transition(s,request(s,target),now=NOW,online=True,verify=lambda _:True,**kw)
    def test_candidate_chain_and_refresh(self):
        state=self.initial;events=[]
        for target in ['REVIEWABLE','AUTHORIZED','ENABLED']:
            state,e=self.advance(state,target);events.append(e)
            self.assertFalse(e['production_release_enabled'])
        self.assertEqual(restore(self.initial,events,trusted_head=state.head,verify=lambda _:True),state)
    def test_invalid_state_combinations(self):
        for target in ['AUTHORIZED','ENABLED','CURRENT','UNKNOWN','black','DRAFT',None]:
            with self.subTest(target=target),self.assertRaises(Rejected):
                transition(self.initial,request(self.initial,target),now=NOW,online=True,verify=lambda _:True)
    def test_context_binding(self):
        for k in ['release_id','source_version','policy_digest','citadel_id','world_id']:
            with self.subTest(k=k),self.assertRaises(Rejected):
                transition(self.initial,request(self.initial,**{k:'other'}),now=NOW,online=True,verify=lambda _:True)
    def test_replay_and_concurrent_tabs(self):
        r=request(self.initial);a,_=self.advance(self.initial)
        for stale in [r,dict(r,request_id='other-tab')]:
            with self.assertRaisesRegex(Rejected,'REPLAY_OR_CONFLICT'):
                transition(a,stale,now=NOW,online=True,verify=lambda _:True)
    def test_no_adapter_and_failed_verifier(self):
        def failed(_): raise TimeoutError()
        for verifier in [None,lambda _:False,lambda _:1,failed]:
            with self.assertRaisesRegex(Rejected,'UNVERIFIED_AUTHORITY'):
                transition(self.initial,request(self.initial),now=NOW,online=True,verify=verifier)
    def test_offline(self):
        with self.assertRaisesRegex(Rejected,'UNKNOWN_OFFLINE'):
            transition(self.initial,request(self.initial),now=NOW,verify=lambda _:True)
    def test_delayed_expired_future_and_long_requests(self):
        for changes in [dict(expires_at=NOW),dict(issued_at='2026-09-26T14:01:00Z'),dict(expires_at='2026-09-27T14:00:00Z')]:
            with self.assertRaises(Rejected): transition(self.initial,request(self.initial,**changes),now=NOW,online=True,verify=lambda _:True)
    def test_revocation_terminal(self):
        s,_=self.advance(self.initial,'REVOKED')
        with self.assertRaisesRegex(Rejected,'INVALID_TRANSITION'): self.advance(s)
    def test_changed_replayed_history(self):
        s,e=self.advance(self.initial)
        e['to']='ENABLED'
        with self.assertRaisesRegex(Rejected,'TAMPERED_HISTORY'): restore(self.initial,[e],trusted_head=s.head,verify=lambda _:True)
    def test_truncated_or_unanchored_history(self):
        s,e=self.advance(self.initial)
        for events,head in [([],s.head),([e],None),([e],'c'*64)]:
            with self.assertRaises(Rejected): restore(self.initial,events,trusted_head=head,verify=lambda _:True)
    def test_invalid_contract(self):
        for changes in [dict(schema_version='future'),dict(extra=True),dict(sequence=True),dict(request_id='')]:
            with self.assertRaises(Rejected): transition(self.initial,request(self.initial,**changes),now=NOW,online=True,verify=lambda _:True)
    def test_domain_separation(self):
        self.assertNotEqual(digest('release_transition',{}),digest('freshness_observation',{}))
    def test_no_floats(self):
        with self.assertRaises(Rejected): digest('x',{'bad':float('nan')})
    def test_invalid_genesis_identity(self):
        for fields in [dict(release_id=[]),dict(citadel_id='OTHER'),dict(world_id='OTHER')]:
            values=dict(release_id='test-only',source_version=SOURCE,policy_digest=POLICY);values.update(fields)
            with self.assertRaises(Rejected): Release(**values)

class FreshnessTests(unittest.TestCase):
    def setUp(self):
        self.record=dict(schema_version=PROFILE,source_version=SOURCE,generated_at='2026-09-26T13:00:00Z',verified_at=NOW,valid_for_seconds=3600,revoked_at=None)
    def check(self,**kwargs):
        return freshness(self.record,now=kwargs.pop('now',NOW),source_version=kwargs.pop('source_version',SOURCE),**kwargs)
    def test_current_requires_all_trust_inputs(self):
        self.assertEqual(self.check(online=True,verified_receipt=True,revocation_known=True),'CURRENT')
        for missing in ['online','verified_receipt','revocation_known']:
            flags=dict(online=True,verified_receipt=True,revocation_known=True);flags.pop(missing)
            self.assertEqual(self.check(**flags),'UNKNOWN')
    def test_expiry_boundary(self): self.assertEqual(self.check(now='2026-09-26T15:00:00Z',verified_receipt=True),'STALE')
    def test_null_verification_unknown(self):
        self.record['verified_at']=None
        self.assertEqual(self.check(online=True,verified_receipt=True,revocation_known=True),'UNKNOWN')
    def test_revocation_beats_offline(self):
        self.record['revoked_at']=NOW
        self.assertEqual(self.check(verified_receipt=True),'REVOKED')
        self.assertEqual(self.check(),'UNKNOWN')
    def test_version_and_clock_mismatch(self):
        self.assertEqual(self.check(source_version='c'*64,verified_receipt=True),'UNKNOWN')
        self.assertEqual(self.check(now='2026-09-26T13:59:59Z',verified_receipt=True),'UNKNOWN')
    def test_invalid_ttl(self):
        for ttl in [None,0,-1,86401,True,1.5,'3600']:
            self.record['valid_for_seconds']=ttl
            self.assertEqual(self.check(verified_receipt=True),'UNKNOWN')
    def test_invalid_times_and_unknown_fields(self):
        for stamp in ['2026-02-30T00:00:00Z','2026-09-26','']:
            self.record['verified_at']=stamp
            self.assertEqual(self.check(verified_receipt=True),'UNKNOWN')
        self.record['extra']=True;self.assertEqual(self.check(),'UNKNOWN')
    def test_history_retains_old_state(self):
        before=copy.deepcopy(self.record);a=observation(None,self.record,'CURRENT',NOW)
        self.record['verified_at']=None;b=observation(a,self.record,'UNKNOWN',NOW)
        self.assertEqual(a['record'],before);self.assertEqual(b['previous_digest'],a['digest'])
        a['status']='REVOKED'
        with self.assertRaises(Rejected): observation(a,self.record,'UNKNOWN',NOW)
    def test_empty_history_is_not_a_reset(self):
        with self.assertRaises(Rejected): observation({},self.record,'UNKNOWN',NOW)

if __name__=='__main__': unittest.main()
