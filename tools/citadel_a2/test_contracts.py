"""Executable A2 reason vectors against both independent A1 implementations."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contracts import ROOT, REGISTRY, validate_receipt

sys.path.insert(0,str(ROOT/'tools/citadel_a1'))
from verify import verify, digest, without

BUNDLE=json.loads((ROOT/'verification/citadel-a1/bundle.json').read_text(encoding='utf-8'))
EXPECTED=json.loads((ROOT/'verification/citadel-a1/expected.json').read_text(encoding='utf-8'))
VECTORS=json.loads((ROOT/'verification/citadel-a2/reason-vectors-v0.1.json').read_text(encoding='utf-8'))

class Contracts(unittest.TestCase):
    def test_all_reason_vectors(self):
        binary=os.environ.get('CITADEL_A1_BINARY')
        self.assertTrue(binary,'CITADEL_A1_BINARY required: differential gate cannot be skipped')
        self.assertEqual({x['reason'] for x in VECTORS['cases']},set(REGISTRY['reasons']))
        for case in VECTORS['cases']:
            with self.subTest(reason=case['reason']):
                bundle=copy.deepcopy(BUNDLE)
                for mutation in case['mutations']:
                    obj=bundle
                    for key in mutation['path'][:-1]:obj=obj[int(key)] if isinstance(obj,list) else obj[key]
                    key=mutation['path'][-1]
                    obj[int(key) if isinstance(obj,list) else key]=mutation['value']
                head=case.get('head_anchor',EXPECTED['head_digest'])
                manifest=case.get('manifest_anchor',EXPECTED['manifest_digest'])
                if case.get('rehash'):
                    previous=None
                    for record in bundle['records']:
                        record['previous_digest']=previous
                        record['payload_digest']=digest('PAYLOAD',record['payload'])
                        previous=record['record_digest']=digest('RECORD',without(record,'record_digest'))
                    head=previous
                raw=case.get('raw',json.dumps(bundle,ensure_ascii=False)).encode('utf-8')
                python=verify(raw,manifest,head)
                self.assertEqual((python['result'],python['reason']),(case['result'],case['reason']))
                self.assertTrue(validate_receipt(python))
                with tempfile.TemporaryDirectory() as tmp:
                    path=Path(tmp)/'bundle.json';path.write_bytes(raw)
                    result=subprocess.run([binary,str(path),manifest,head],capture_output=True,check=False)
                    self.assertEqual(json.loads(result.stdout),python)
                    self.assertEqual(result.returncode,0 if case['result']=='VALID' else 1)

    def test_receipt_rejects_unproven_claims(self):
        good=verify(json.dumps(BUNDLE).encode(),EXPECTED['manifest_digest'],EXPECTED['head_digest'])
        self.assertTrue(validate_receipt(good))
        for key,value in [('authority','VALID'),('scope','FULL_CITADEL'),('reason','NEW_UNKNOWN_CODE'),('result','INVALID'),('extra',None),('reason',None),('reason',[])]:
            bad={**good,key:value};self.assertFalse(validate_receipt(bad))
        for key in good:
            bad=dict(good);del bad[key];self.assertFalse(validate_receipt(bad))

    def test_schema_matches_registry(self):
        schema=json.loads((ROOT/'specs/citadel-a2/verification-result.schema.json').read_text())
        self.assertFalse(schema['additionalProperties'])
        self.assertEqual(set(schema['required']),set(schema['properties']))
        mapping={reason:branch['properties']['result']['const'] for branch in schema['oneOf'] for reason in branch['properties']['reason']['enum']}
        self.assertEqual(mapping,REGISTRY['reasons'])

if __name__=='__main__':unittest.main()
