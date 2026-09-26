"""Offline checksum gate for an unsigned A2 release candidate, never release approval."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/citadel_a1'))
from verify import canonical, pairs, reject, integer, validate_json, verify, MAX_BYTES

FILES=('bundle.json','expected.json','manifest.json')
KEYS=set('descriptor_version status source_commit citadel_id world_id manifest_digest head_digest canonical_encoding cryptographic_profile files signature'.split())

def parse(raw):
    if len(raw)>MAX_BYTES:raise ValueError('descriptor too large')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_float=reject,parse_constant=reject,parse_int=integer)
    validate_json(value)
    return value

def descriptor_digest(value):
    return hashlib.sha256(b'PALACO:CITADEL:RELEASE-DESCRIPTOR:A2\0'+canonical(value)).hexdigest()

def result(status,reason,integrity='UNKNOWN'):
    return dict(result=status,reason=reason,scope='A2_RELEASE_CANDIDATE',artifact_integrity=integrity,release_authority='UNKNOWN',signatures='UNKNOWN',production_release=False)

def bounded_file(root,name):
    path=root/name
    if path.is_symlink() or not path.is_file():raise ValueError('missing or linked artifact')
    with path.open('rb') as source:data=source.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:raise ValueError('oversized artifact')
    return data

def check(raw,root,expected_digest,expected_commit):
    """External anchors check declared commit and bytes, not Git ancestry or authority."""
    try:
        value=parse(raw)
        if not isinstance(value,dict) or set(value)!=KEYS:return result('INVALID','DESCRIPTOR_FIELDS')
        if not isinstance(value['descriptor_version'],str):return result('INVALID','DESCRIPTOR_VERSION_TYPE')
        if value['descriptor_version']!='0.1':return result('UNKNOWN','UNSUPPORTED_DESCRIPTOR_VERSION')
        if value['status']!='DRAFT':return result('INVALID','CANDIDATE_STATUS_REQUIRED')
        if not isinstance(value['source_commit'],str) or not re.fullmatch('[0-9a-f]{40}',value['source_commit']):return result('INVALID','COMMIT_FORMAT')
        if not expected_digest or not expected_commit:return result('INCOMPLETE','EXTERNAL_RELEASE_ANCHORS_REQUIRED')
        if value['source_commit']!=expected_commit or descriptor_digest(value)!=expected_digest:return result('CONFLICT','RELEASE_ANCHOR_CONFLICT')
        expected_files=value['files']
        if not isinstance(expected_files,list) or len(expected_files)!=len(FILES):return result('INVALID','ARTIFACT_INVENTORY')
        contents={}
        for entry,name in zip(expected_files,FILES):
            if not isinstance(entry,dict) or set(entry)!={'name','sha256'} or entry['name']!=name:return result('INVALID','ARTIFACT_INVENTORY')
            data=bounded_file(Path(root),name)
            if hashlib.sha256(data).hexdigest()!=entry['sha256']:return result('INVALID','ARTIFACT_DIGEST')
            contents[name]=data
        bundle=parse(contents['bundle.json']);manifest=parse(contents['manifest.json']);expected=parse(contents['expected.json'])
        if bundle['manifest']!=manifest:return result('INVALID','MANIFEST_ARTIFACT_CONFLICT')
        for key in ('citadel_id','world_id','manifest_digest','canonical_encoding','cryptographic_profile'):
            if value[key]!=manifest[key]:return result('CONFLICT','RELEASE_CONTEXT_CONFLICT')
        if value['head_digest']!=expected['head_digest'] or value['manifest_digest']!=expected['manifest_digest']:return result('CONFLICT','RELEASE_CONTEXT_CONFLICT')
        receipt=verify(contents['bundle.json'],value['manifest_digest'],value['head_digest'])
        if receipt['result']!='VALID':return result(receipt['result'],'BUNDLE_'+receipt['reason'])
        if value['signature'] is not None:return result('UNKNOWN','SIGNATURE_PROFILE_NOT_IMPLEMENTED','VALID')
        return result('INCOMPLETE','DESIGNATED_REVIEWER_AND_SIGNATURE_POLICY_REQUIRED','VALID')
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OSError):
        return result('INVALID','MALFORMED_OR_MISSING_RELEASE_MATERIAL')

if __name__=='__main__':
    if len(sys.argv)!=5:
        print('usage: release_candidate.py DESCRIPTOR ARTIFACT_DIRECTORY EXPECTED_DESCRIPTOR_DIGEST EXPECTED_COMMIT',file=sys.stderr)
        sys.exit(64)
    try:
        with open(sys.argv[1],'rb') as source:raw=source.read(MAX_BYTES+1)
        receipt=check(raw,Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    except OSError:receipt=result('INVALID','DESCRIPTOR_UNREADABLE')
    print(json.dumps(receipt))
    # This candidate verifier has no production approval capability.
    sys.exit(1)
