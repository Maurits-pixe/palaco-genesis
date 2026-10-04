"""A2 signature-profile candidate. Verifies evidence; never deploys or grants activation."""
import hashlib
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from release_candidate import parse, canonical, check, MAX_BYTES

PROFILE = 'ED25519-A2-APPROVALS-0.1'
POLICY_KEYS = set('policy_version signature_profile governance_phase required_distinct_reviewers citadel_id world_id reviewers'.split())
ENVELOPE_KEYS = set('signature_profile policy_digest descriptor_digest source_commit citadel_id world_id release_sequence previous_release_digest approvals'.split())
REVIEWER_KEYS = {'reviewer_id','key_id','public_key_hex','status'}
APPROVAL_KEYS = {'reviewer_id','key_id','signature_hex'}
IDENTIFIER = re.compile(r'[A-Za-z0-9_:./-]{1,128}\Z')

def hex_value(value,length):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None

def identifier(value):
    return isinstance(value,str) and IDENTIFIER.fullmatch(value) is not None

def policy_digest(policy):
    return hashlib.sha256(b'PALACO:CITADEL:RELEASE-POLICY:A2\0'+canonical(policy)).hexdigest()

def approval_message(envelope,reviewer_id,key_id):
    """Bind each signer identity/key as well as release and policy context."""
    statement={k:v for k,v in envelope.items() if k!='approvals'}
    statement.update(reviewer_id=reviewer_id,key_id=key_id)
    return b'PALACO:CITADEL:RELEASE-APPROVAL:A2\0'+canonical(statement)

def release_digest(envelope):
    """Next continuity anchor includes the ordered policy-required approvals."""
    return hashlib.sha256(b'PALACO:CITADEL:APPROVED-RELEASE:A2\0'+canonical(envelope)).hexdigest()

def result(status,reason):
    return dict(result=status,reason=reason,scope='A2_SIGNATURES_AND_ARTIFACT_INTEGRITY',production_release=False)

def verify_approvals(envelope_raw,policy_raw,descriptor_raw,artifact_directory,
                     expected_policy_digest,expected_descriptor_digest,expected_commit,
                     last_sequence,previous_release_digest):
    """All expected anchors and continuity state must come from trusted external storage."""
    try:
        policy=parse(policy_raw);envelope=parse(envelope_raw)
        if not isinstance(policy,dict) or set(policy)!=POLICY_KEYS:return result('INVALID','POLICY_FIELDS')
        if not isinstance(envelope,dict) or set(envelope)!=ENVELOPE_KEYS:return result('INVALID','APPROVAL_ENVELOPE_FIELDS')
        if not isinstance(policy['policy_version'],str):return result('INVALID','POLICY_VERSION_TYPE')
        if policy['policy_version']!='0.2' or policy['signature_profile']!=PROFILE or envelope['signature_profile']!=PROFILE:
            return result('UNKNOWN','UNSUPPORTED_SIGNATURE_POLICY')
        if policy['governance_phase']!='INTERIM':return result('UNKNOWN','GOVERNANCE_HANDOVER_NOT_IMPLEMENTED')
        threshold=policy['required_distinct_reviewers']
        if type(threshold) is not int or threshold not in (1,2):
            return result('INVALID','UNSUPPORTED_INTERIM_THRESHOLD')
        if not all(identifier(policy[k]) for k in ('citadel_id','world_id')):return result('INVALID','POLICY_CONTEXT')
        if not expected_policy_digest or not expected_descriptor_digest or not expected_commit:
            return result('INCOMPLETE','TRUSTED_ANCHORS_REQUIRED')
        if not hex_value(expected_policy_digest,64) or not hex_value(expected_descriptor_digest,64) or not hex_value(expected_commit,40):
            return result('INVALID','TRUSTED_ANCHOR_FORMAT')
        if policy_digest(policy)!=expected_policy_digest or envelope['policy_digest']!=expected_policy_digest:
            return result('CONFLICT','POLICY_ANCHOR_CONFLICT')
        if envelope['descriptor_digest']!=expected_descriptor_digest or envelope['source_commit']!=expected_commit:
            return result('CONFLICT','DESCRIPTOR_ANCHOR_CONFLICT')
        if any(envelope[k]!=policy[k] for k in ('citadel_id','world_id')):return result('CONFLICT','APPROVAL_CONTEXT_CONFLICT')
        if type(last_sequence) is not int or last_sequence<0 or last_sequence>=9007199254740991:
            return result('INVALID','TRUSTED_SEQUENCE_FORMAT')
        if (last_sequence==0 and previous_release_digest is not None) or (last_sequence>0 and not hex_value(previous_release_digest,64)):
            return result('INVALID','TRUSTED_PREVIOUS_RELEASE_FORMAT')
        if type(envelope['release_sequence']) is not int or envelope['release_sequence']<1:
            return result('INVALID','RELEASE_SEQUENCE_FORMAT')
        if envelope['release_sequence']<=last_sequence:return result('INVALID','RELEASE_ROLLBACK_OR_REPLAY')
        if envelope['release_sequence']!=last_sequence+1:return result('INCOMPLETE','RELEASE_SEQUENCE_GAP')
        if envelope['previous_release_digest']!=previous_release_digest:return result('CONFLICT','PREVIOUS_RELEASE_CONFLICT')
        reviewers=policy['reviewers']
        if not isinstance(reviewers,list):return result('INVALID','REVIEWER_POLICY_FORMAT')
        if len(reviewers)<threshold:return result('INCOMPLETE','REQUIRED_REVIEWERS_NOT_DESIGNATED')
        if len(reviewers)!=threshold:return result('INVALID','REVIEWER_COUNT_POLICY_CONFLICT')
        trusted={};key_ids=set();public_keys=set()
        for reviewer in reviewers:
            if not isinstance(reviewer,dict) or set(reviewer)!=REVIEWER_KEYS:return result('INVALID','REVIEWER_POLICY_FORMAT')
            if not identifier(reviewer['reviewer_id']) or not identifier(reviewer['key_id']) or not hex_value(reviewer['public_key_hex'],64):
                return result('INVALID','REVIEWER_KEY_FORMAT')
            if reviewer['status'] not in ('ACTIVE','REVOKED'):return result('INVALID','REVIEWER_STATUS')
            if reviewer['reviewer_id'] in trusted or reviewer['key_id'] in key_ids or reviewer['public_key_hex'] in public_keys:
                return result('INVALID','REVIEWERS_AND_KEYS_MUST_BE_DISTINCT')
            trusted[reviewer['reviewer_id']]=reviewer;key_ids.add(reviewer['key_id']);public_keys.add(reviewer['public_key_hex'])
        approvals=envelope['approvals']
        if not isinstance(approvals,list):return result('INVALID','APPROVALS_ARRAY_REQUIRED')
        if len(approvals)<threshold:return result('INCOMPLETE','REQUIRED_APPROVALS_MISSING')
        if len(approvals)!=threshold:return result('INVALID','APPROVAL_COUNT_POLICY_CONFLICT')
        seen=[]
        for approval in approvals:
            if not isinstance(approval,dict) or set(approval)!=APPROVAL_KEYS:return result('INVALID','APPROVAL_FIELDS')
            rid=approval['reviewer_id']
            if not identifier(rid) or not identifier(approval['key_id']) or not hex_value(approval['signature_hex'],128):
                return result('INVALID','APPROVAL_FORMAT')
            if rid in seen:return result('INVALID','DUPLICATE_REVIEWER_APPROVAL')
            reviewer=trusted.get(rid)
            if reviewer is None or reviewer['key_id']!=approval['key_id']:return result('INVALID','UNTRUSTED_REVIEWER_KEY')
            if reviewer['status']!='ACTIVE':return result('INVALID','REVIEWER_KEY_REVOKED')
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(reviewer['public_key_hex'])).verify(
                bytes.fromhex(approval['signature_hex']),approval_message(envelope,rid,approval['key_id']))
            seen.append(rid)
        if seen!=sorted(seen):return result('INVALID','APPROVAL_ORDER')
        descriptor=parse(descriptor_raw)
        if not isinstance(descriptor,dict) or any(descriptor.get(k)!=policy[k] for k in ('citadel_id','world_id')):
            return result('CONFLICT','ARTIFACT_POLICY_CONTEXT_CONFLICT')
        integrity=check(descriptor_raw,artifact_directory,expected_descriptor_digest,expected_commit)
        if integrity['reason']!='DESIGNATED_REVIEWER_AND_SIGNATURE_POLICY_REQUIRED':
            return result(integrity['result'],'ARTIFACT_'+integrity['reason'])
        receipt=result('VALID','POLICY_APPROVALS_AND_ARTIFACTS_MATCH')
        receipt['release_digest']=release_digest(envelope)
        return receipt
    except InvalidSignature:return result('INVALID','INVALID_APPROVAL_SIGNATURE')
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OSError):
        return result('INVALID','MALFORMED_APPROVAL_MATERIAL')

def read(path):
    with Path(path).open('rb') as source:return source.read(MAX_BYTES+1)

if __name__=='__main__':
    import json
    if len(sys.argv)!=10:
        print('usage: verify_approvals.py APPROVALS POLICY DESCRIPTOR ARTIFACT_DIR EXPECTED_POLICY_DIGEST EXPECTED_DESCRIPTOR_DIGEST EXPECTED_COMMIT LAST_SEQUENCE PREVIOUS_RELEASE_DIGEST_OR_NONE',file=sys.stderr)
        sys.exit(64)
    try:
        receipt=verify_approvals(read(sys.argv[1]),read(sys.argv[2]),read(sys.argv[3]),sys.argv[4],
            sys.argv[5],sys.argv[6],sys.argv[7],int(sys.argv[8]),None if sys.argv[9]=='NONE' else sys.argv[9])
    except (OSError,ValueError):receipt=result('INVALID','APPROVAL_INPUT_UNREADABLE')
    print(json.dumps(receipt))
    # Zero means the narrow evidence check passed, never deployment approval.
    sys.exit(0 if receipt['result']=='VALID' else 1)
