"""Mutation matrix for the independent verifier, optionally cross-checked with Rust."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from verify import canonical, digest, verify, without

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = json.loads((ROOT / 'verification/citadel-a1/bundle.json').read_text(encoding='utf-8'))
EXPECTED = json.loads((ROOT / 'verification/citadel-a1/expected.json').read_text(encoding='utf-8'))

def rehash(bundle):
    previous = None
    for r in bundle['records']:
        r['previous_digest'] = previous
        r['payload_digest'] = digest('PAYLOAD', r['payload'])
        r['record_digest'] = digest('RECORD', without(r,'record_digest'))
        previous = r['record_digest']
    return previous

class VerificationTests(unittest.TestCase):
    def check(self, bundle, status, head=None, manifest=None):
        raw = bundle if isinstance(bundle, bytes) else json.dumps(bundle, ensure_ascii=False).encode('utf-8')
        manifest = EXPECTED['manifest_digest'] if manifest is None else manifest
        head = EXPECTED['head_digest'] if head is None else head
        receipt = verify(raw, manifest, head)
        self.assertEqual(receipt['result'],status,receipt)
        for field in ('identity','authority','signatures','current_validity','archive_inclusion'):
            self.assertEqual(receipt[field],'UNKNOWN')
        binary = os.environ.get('CITADEL_A1_BINARY')
        if binary:
            with tempfile.TemporaryDirectory() as directory:
                file = Path(directory) / 'case.json'
                file.write_bytes(raw)
                process = subprocess.run([binary,str(file),manifest,head],capture_output=True,text=True,check=False)
                rust = json.loads(process.stdout)
                self.assertEqual(rust['result'],receipt['result'],rust)
                self.assertEqual(process.returncode,0 if status=='VALID' else 1)

    def test_frozen_vector(self):
        self.check(BUNDLE,'VALID')
        for i,r in enumerate(BUNDLE['records']):
            self.assertEqual(canonical(r['payload']).decode(),EXPECTED['payload_canonical_utf8'][i])
            self.assertEqual(digest('PAYLOAD',r['payload']),EXPECTED['payload_digests'][i])

    def test_malformed_profile(self):
        for raw in [b'{"a":1,"a":2}',b'{"a":1.0}',b'{"a":1e3}',b'{"a":NaN}',b'{"a":9007199254740992}',b'{"a":"\\ud800"}',b'{"A":1}',b'[]',b'\xff']:
            with self.subTest(raw=raw):self.check(raw,'INVALID')

    def test_tamper(self):
        v=copy.deepcopy(BUNDLE);v['records'][1]['payload']['sample_count']=4;self.check(v,'INVALID')

    def test_truncate(self):
        v=copy.deepcopy(BUNDLE);v['records'].pop();self.check(v,'INCOMPLETE')

    def test_missing_prefix(self):
        v=copy.deepcopy(BUNDLE);v['records'].pop(0);self.check(v,'INCOMPLETE')

    def test_duplicate(self):
        v=copy.deepcopy(BUNDLE);v['records'][1]['record_id']=v['records'][0]['record_id'];self.check(v,'CONFLICT')

    def test_empty(self):
        v=copy.deepcopy(BUNDLE);v['records']=[];self.check(v,'UNKNOWN')

    def test_resource_context(self):
        v=copy.deepcopy(BUNDLE);v['records'][0]['world_id']='OTHER';self.check(v,'CONFLICT')

    def test_missing_dependency(self):
        v=copy.deepcopy(BUNDLE);v['records'][2]['evidence_refs']=['absent'];self.check(v,'INCOMPLETE',head=rehash(v))

    def test_wrong_dependency_type(self):
        v=copy.deepcopy(BUNDLE);v['records'][2]['authorization_ref']=v['records'][1]['record_id'];self.check(v,'INVALID',head=rehash(v))

    def test_self_reference(self):
        v=copy.deepcopy(BUNDLE);v['records'][2]['provenance_refs']=[v['records'][2]['record_id']];self.check(v,'INVALID',head=rehash(v))

    def test_unknown_profile(self):
        v=copy.deepcopy(BUNDLE);v['manifest']['cryptographic_profile']='future';self.check(v,'UNKNOWN')

    def test_signature_not_silently_accepted(self):
        v=copy.deepcopy(BUNDLE);v['records'][2]['signature']={'value':'not-a-signature'};self.check(v,'UNKNOWN',head=rehash(v))

    def test_anchor_required(self):
        self.check(BUNDLE,'INCOMPLETE',manifest='',head='')
        self.check(BUNDLE,'CONFLICT',manifest='0'*64)

    def test_display_time_not_used_for_order_or_authority(self):
        v=copy.deepcopy(BUNDLE);v['records'][2]['created_at_display']='1900-01-01T00:00:00Z';self.check(v,'VALID',head=rehash(v))

    def test_explicit_nullable_fields(self):
        v=copy.deepcopy(BUNDLE);del v['records'][0]['authorization_ref'];self.check(v,'INVALID')

    def test_oversize(self):
        self.check(b' '*1_048_577,'INVALID')

if __name__=='__main__':unittest.main()
