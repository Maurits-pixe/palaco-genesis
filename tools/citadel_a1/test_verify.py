"""Mutation matrix for the independent verifier, optionally cross-checked with Rust."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
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
                self.assertEqual(rust,receipt)
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

    def test_contract_gate_mutations(self):
        for field, value, status in [('schema_version','9','UNKNOWN'), ('schema_version',None,'INVALID'), ('citadel_id','OTHER','CONFLICT'), ('previous_digest','0'*64,'INVALID'), ('extra',None,'INVALID')]:
            with self.subTest(field=field,value=value):
                v=copy.deepcopy(BUNDLE);v['records'][0][field]=value;self.check(v,status)
        for value in ('9',None):
            v=copy.deepcopy(BUNDLE);v['manifest']['schema_version']=value
            self.check(v,'UNKNOWN' if isinstance(value,str) else 'INVALID')
        v=copy.deepcopy(BUNDLE);v['manifest']['extra']=None;self.check(v,'INVALID')
        v=copy.deepcopy(BUNDLE);v['records'][2]['provenance_refs']=['missing-source'];self.check(v,'INCOMPLETE',head=rehash(v))

    def test_empty_null_and_field_order(self):
        v=copy.deepcopy(BUNDLE);v['records'][0]['payload']={'empty':'','array':[],'object':{},'nullable':None}
        self.check(v,'VALID',head=rehash(v))
        def reverse(value):
            if isinstance(value,dict):return {k:reverse(v) for k,v in reversed(list(value.items()))}
            if isinstance(value,list):return [reverse(v) for v in value]
            return value
        self.check(reverse(BUNDLE),'VALID')

    def test_frozen_blank_definition(self):
        points=list(range(0x21))+[0x85,0xa0,0x1680,*range(0x2000,0x200b),0x2028,0x2029,0x202f,0x205f,0x3000]
        for point in points:
            with self.subTest(point=point):
                v=copy.deepcopy(BUNDLE);v['records'][-1]['created_at_display']=chr(point)
                self.check(v,'INVALID',head=rehash(v))
        for field in ('purpose','edition','presentation'):
            v=copy.deepcopy(BUNDLE);v['manifest'][field]=['\x1c'] if field=='presentation' else '\x1c'
            self.check(v,'INVALID')
        v=copy.deepcopy(BUNDLE);v['records'][-1]['created_at_display']='\u200b'
        self.check(v,'VALID',head=rehash(v))

    def test_context_is_bound_by_record_digest(self):
        original=without(BUNDLE['records'][0],'record_digest')
        for field in ('record_type','schema_version','citadel_id','world_id','manifest_digest'):
            value=copy.deepcopy(original);value[field]='different'
            self.assertNotEqual(digest('RECORD',value),digest('RECORD',original))
            self.assertEqual(digest('PAYLOAD',value['payload']),digest('PAYLOAD',original['payload']))

    def test_reference_files_never_change(self):
        checks=json.loads((ROOT/'verification/citadel-a1/frozen-sha256-v1.json').read_text())
        for name,expected in checks.items():
            self.assertEqual(hashlib.sha256((ROOT/'verification/citadel-a1'/name).read_bytes()).hexdigest(),expected)
        process=subprocess.run([sys.executable,str(ROOT/'tools/citadel_a1/generate_vector.py')],capture_output=True,check=False)
        self.assertNotEqual(process.returncode,0)
        for name,expected in checks.items():
            self.assertEqual(hashlib.sha256((ROOT/'verification/citadel-a1'/name).read_bytes()).hexdigest(),expected)

    def test_canonical_bytes_and_all_domains(self):
        binary=os.environ.get('CITADEL_A1_CANONICAL_BINARY')
        if not binary:self.skipTest('set CITADEL_A1_CANONICAL_BINARY for direct byte comparison')
        values=[None,{},[],{'z':None,'a':'','b':False,'c':True}, {'unicode':'é e\u0301 水 🏰\u2028\u2029'}, {'controls':''.join(chr(i) for i in range(32))}, {'n':-9007199254740991,'p':9007199254740991}, without(BUNDLE['manifest'],'manifest_digest')]
        values += [without(r,'record_digest') for r in BUNDLE['records']]
        for value in values:
            with self.subTest(value=value),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'value.json';path.write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8')
                process=subprocess.run([binary,str(path)],capture_output=True,check=False)
                self.assertEqual(process.returncode,0,process.stderr)
                rust=json.loads(process.stdout)
                self.assertEqual(bytes(rust['canonical_bytes']),canonical(value))
                for domain in ('MANIFEST','PAYLOAD','RECORD'):
                    self.assertEqual(rust[domain.lower()+'_digest'],digest(domain,value))
        for depth,valid in ((64,True),(65,False)):
            value=0
            for _ in range(depth):value=[value]
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'deep.json';path.write_text(json.dumps(value),encoding='utf-8')
                process=subprocess.run([binary,str(path)],capture_output=True,check=False)
                self.assertEqual(process.returncode==0,valid)
                if valid:self.assertEqual(bytes(json.loads(process.stdout)['canonical_bytes']),canonical(value))
                else:
                    with self.assertRaises(ValueError):canonical(value)

if __name__=='__main__':unittest.main()
