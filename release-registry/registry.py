"""Draft, offline contract reference. Never deploys or grants production authority.

The service supplies authenticated verifier receipts and trusted time/anchors.
No trust flag from a browser or untrusted JSON is accepted as an authorization.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import re

PROFILE = 'PALACO-REGISTRY-0.1'
STATES = {'DRAFT', 'REVIEWABLE', 'AUTHORIZED', 'ENABLED', 'REVOKED'}
NEXT = {'DRAFT': 'REVIEWABLE', 'REVIEWABLE': 'AUTHORIZED', 'AUTHORIZED': 'ENABLED'}
HEX = re.compile(r'^[0-9a-f]{64}$')

class Rejected(ValueError):
    pass

def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        raise Rejected('INVALID_TIME')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Rejected('INVALID_TIME') from exc

def canonical(value):
    # A deliberately narrow profile, not a replacement for the A1 Rust contract.
    def check(v):
        if v is None or type(v) in (str, bool):
            return
        if type(v) is int and abs(v) <= 9007199254740991:
            return
        if type(v) is list:
            for item in v: check(item)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for item in v.values(): check(item)
            return
        raise Rejected('UNSUPPORTED_CANONICAL_VALUE')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def digest(kind, value):
    return hashlib.sha256(b'PALACO-REGISTRY\x00' + PROFILE.encode() + b'\x00' + kind.encode() + b'\x00' + canonical(value)).hexdigest()

@dataclass(frozen=True)
class Release:
    release_id: str
    source_version: str
    policy_digest: str
    state: str = 'DRAFT'
    sequence: int = 0
    head: str | None = None
    last_at: str | None = None
    citadel_id: str = 'EVA-LA-001'
    world_id: str = 'WORLD-EVA-001'

    def __post_init__(self):
        if not isinstance(self.release_id,str) or not self.release_id.strip() or not isinstance(self.source_version, str) or not HEX.fullmatch(self.source_version):
            raise Rejected('INVALID_RELEASE_IDENTITY')
        if self.citadel_id != 'EVA-LA-001' or self.world_id != 'WORLD-EVA-001':
            raise Rejected('CONTEXT_MISMATCH')
        if not isinstance(self.policy_digest, str) or not HEX.fullmatch(self.policy_digest):
            raise Rejected('INVALID_POLICY')
        if self.state not in STATES or type(self.sequence) is not int or self.sequence < 0:
            raise Rejected('INVALID_STATE')
        if self.sequence == 0 and (self.state != 'DRAFT' or self.head is not None or self.last_at is not None):
            raise Rejected('INVALID_GENESIS')
        if self.sequence > 0 and (not isinstance(self.head, str) or not HEX.fullmatch(self.head) or self.last_at is None):
            raise Rejected('INCOMPLETE_HISTORY')

def transition(current, request, *, now, online=False, verify=None):
    """verify(bytes) is a trusted server adapter; no adapter means deny.

    Returns candidate state + audit event. Caller must atomically persist both
    with expected head/sequence; this pure reducer is NOT a concurrent store.
    """
    fields = {'schema_version','request_id','release_id','source_version','policy_digest','citadel_id','world_id','target','sequence','previous_digest','issued_at','expires_at'}
    if type(request) is not dict or set(request) != fields or request['schema_version'] != PROFILE:
        raise Rejected('INVALID_CONTRACT')
    if not isinstance(request['request_id'], str) or not request['request_id'].strip():
        raise Rejected('INVALID_REQUEST_ID')
    for key in ('release_id','source_version','policy_digest','citadel_id','world_id'):
        if request[key] != getattr(current,key): raise Rejected('CONTEXT_MISMATCH')
    if type(request['sequence']) is not int or request['sequence'] != current.sequence+1 or request['previous_digest'] != current.head:
        raise Rejected('REPLAY_OR_CONFLICT')
    at, issued, expires = utc(now), utc(request['issued_at']), utc(request['expires_at'])
    if current.last_at and at < utc(current.last_at): raise Rejected('CLOCK_ROLLBACK')
    if not issued <= at < expires or (expires-issued).total_seconds() > 300:
        raise Rejected('EXPIRED_OR_INVALID_WINDOW')
    if online is not True: raise Rejected('UNKNOWN_OFFLINE')
    target=request['target']
    if current.state == 'REVOKED' or not isinstance(target,str) or (target != 'REVOKED' and NEXT.get(current.state) != target):
        raise Rejected('INVALID_TRANSITION')
    payload = b'PALACO-RELEASE-REQUEST\x00' + canonical(request)
    try:
        verified = callable(verify) and verify(payload) is True
    except Exception:
        verified = False
    if not verified: raise Rejected('UNVERIFIED_AUTHORITY')
    event={'schema_version':PROFILE,'kind':'release_transition','request':dict(request),'from':current.state,'to':target,'recorded_at':now,'production_release_enabled':False}
    head=digest('release_transition',event)
    return replace(current,state=target,sequence=current.sequence+1,head=head,last_at=now), {**event,'digest':head}

def restore(genesis, events, *, trusted_head, verify):
    """Refresh replays history against an independently supplied checkpoint.

    The browser's own localStorage head is never a trusted checkpoint.
    """
    current=genesis
    for event in events:
        if type(event) is not dict or 'request' not in event or 'recorded_at' not in event:
            raise Rejected('INVALID_HISTORY')
        candidate, reproduced=transition(current,event['request'],now=event['recorded_at'],online=True,verify=verify)
        if reproduced != event: raise Rejected('TAMPERED_HISTORY')
        current=candidate
    if not isinstance(trusted_head,str) or current.head != trusted_head: raise Rejected('UNTRUSTED_CHECKPOINT')
    return current

def freshness(record, *, now, source_version, online=False, verified_receipt=False, revocation_known=False):
    """Evaluate scoped freshness; never promote unknown verification to CURRENT.

    verified_receipt/revocation_known are trusted service adapter outputs, not
    client-supplied fields. production integration is intentionally absent.
    """
    fields={'schema_version','source_version','generated_at','verified_at','valid_for_seconds','revoked_at'}
    if type(record) is not dict or set(record)!=fields or record.get('schema_version')!=PROFILE:
        return 'UNKNOWN'
    if record.get('source_version') != source_version or not isinstance(source_version,str) or not HEX.fullmatch(source_version): return 'UNKNOWN'
    try:
        at=utc(now);generated=utc(record['generated_at'])
        ttl=record['valid_for_seconds']
        if type(ttl) is not int or not 0<ttl<=86400: return 'UNKNOWN'
        if record['revoked_at'] is not None:
            revoked=utc(record['revoked_at'])
            if not generated<=revoked<=at: return 'UNKNOWN'
            return 'REVOKED' if verified_receipt is True else 'UNKNOWN'
        checked=utc(record['verified_at'])
        if not generated<=checked<=at: return 'UNKNOWN'
        if verified_receipt is not True: return 'UNKNOWN'
        if (at-checked).total_seconds()>=ttl: return 'STALE'
        if online is not True or revocation_known is not True: return 'UNKNOWN'
        return 'CURRENT'
    except (Rejected,TypeError,ValueError):
        return 'UNKNOWN'

def observation(previous, record, status, at):
    """Append a new observation without erasing the previous record.

    Hash chains detect changes only relative to a separately trusted head.
    Storage, retention and signatures remain release gates.
    """
    if status not in {'CURRENT','STALE','UNKNOWN','REVOKED'}: raise Rejected('INVALID_STATUS')
    utc(at)
    if previous is not None:
        fields={'schema_version','sequence','previous_digest','record','status','observed_at','digest'}
        if type(previous) is not dict or set(previous)!=fields or previous['schema_version']!=PROFILE or type(previous['sequence']) is not int or previous['sequence']<1:
            raise Rejected('INVALID_HISTORY')
        content={k:v for k,v in previous.items() if k!='digest'}
        if previous.get('digest') != digest('freshness_observation',content): raise Rejected('TAMPERED_HISTORY')
        if utc(at)<utc(previous['observed_at']): raise Rejected('CLOCK_ROLLBACK')
    event={'schema_version':PROFILE,'sequence':previous['sequence']+1 if previous else 1,'previous_digest':previous['digest'] if previous else None,'record':json.loads(canonical(record)),'status':status,'observed_at':at}
    return {**event,'digest':digest('freshness_observation',event)}
