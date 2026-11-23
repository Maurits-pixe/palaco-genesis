#!/usr/bin/env python3
"""Offline archive-content sampling verification (claims, not proof of remoteness).

A manifest is independently SHA-256 pinned. A caller-selected index and
fresh nonce bind a signed custodian reply to actual supplied chunk bytes.
No network, trusted clock, randomness, challenge issuance or storage here.
"""
import base64
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN=b"PALACO-ARCHIVE-CONTENT-SAMPLE-V1\x00"
MANIFEST_DOMAIN=b"PALACO-ARCHIVE-CONTENT-MANIFEST-V1\x00"
HEX=re.compile(r"^[0-9a-f]{64}$")
IDENT=re.compile(r"^[a-z][a-z0-9-]{1,63}$")
MAX_CHUNKS=1024
MAX_CHUNK_BYTES=65536
MANIFEST_FIELDS={"schema_version","archive_head_sha256","chunk_size","total_bytes","chunk_sha256"}
CHALLENGE_FIELDS={"schema_version","requester_id","nonce_hex","manifest_sha256","chunk_index",
                  "issued_epoch","expires_epoch"}
REPLY_FIELDS={"challenge","custodian_key_id","chunk_b64","signature_b64"}


def _raw(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def canonical_manifest(body):
    if not isinstance(body,dict) or set(body)!=MANIFEST_FIELDS:
        raise ValueError("invalid-content-manifest-schema")
    if body["schema_version"]!="0.1.0":
        raise ValueError("invalid-content-manifest-version")
    if not isinstance(body["archive_head_sha256"],str) or not HEX.fullmatch(body["archive_head_sha256"]):
        raise ValueError("invalid-content-archive-binding")
    size=body["chunk_size"]
    total=body["total_bytes"]
    chunks=body["chunk_sha256"]
    if type(size) is not int or not 1<=size<=MAX_CHUNK_BYTES:
        raise ValueError("invalid-content-chunk-size")
    if type(total) is not int or not 1<=total<=MAX_CHUNKS*size:
        raise ValueError("invalid-content-size")
    if (not isinstance(chunks,list) or not 1<=len(chunks)<=MAX_CHUNKS
        or len(chunks)!=(total+size-1)//size
        or any(not isinstance(d,str) or not HEX.fullmatch(d) for d in chunks)):
        raise ValueError("invalid-content-chunk-digests")
    return _raw(body)


def manifest_digest(body):
    return hashlib.sha256(MANIFEST_DOMAIN+canonical_manifest(body)).hexdigest()


def canonical_challenge(body):
    if not isinstance(body,dict) or set(body)!=CHALLENGE_FIELDS:
        raise ValueError("invalid-content-challenge-schema")
    if body["schema_version"]!="0.1.0":
        raise ValueError("invalid-content-challenge-version")
    if not isinstance(body["requester_id"],str) or not IDENT.fullmatch(body["requester_id"]):
        raise ValueError("invalid-content-requester")
    for field in ("nonce_hex","manifest_sha256"):
        if not isinstance(body[field],str) or not HEX.fullmatch(body[field]):
            raise ValueError("invalid-content-challenge-digest")
    if type(body["chunk_index"]) is not int or not 0<=body["chunk_index"]<MAX_CHUNKS:
        raise ValueError("invalid-content-chunk-index")
    if (type(body["issued_epoch"]) is not int or type(body["expires_epoch"]) is not int
        or body["issued_epoch"]<1 or body["issued_epoch"]>=body["expires_epoch"]):
        raise ValueError("invalid-content-challenge-interval")
    return _raw(body)


def canonical_reply(body):
    if not isinstance(body,dict) or set(body)!=REPLY_FIELDS:
        raise ValueError("invalid-content-reply-schema")
    canonical_challenge(body["challenge"])
    if not isinstance(body["custodian_key_id"],str) or not HEX.fullmatch(body["custodian_key_id"]):
        raise ValueError("invalid-content-custodian")
    if not isinstance(body["chunk_b64"],str) or len(body["chunk_b64"])>4*((MAX_CHUNK_BYTES+2)//3):
        raise ValueError("invalid-content-chunk-encoding")
    return _raw({k:body[k] for k in REPLY_FIELDS-{"signature_b64"}})


def _out(**kw):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "content_sample_valid":False,"state":"quarantined",**kw}


def verify(manifest, independently_pinned_manifest_hash, expected_archive_head,
           challenge, response, expected_requester, expected_nonce,
           trusted_current_epoch, consumed_nonces, custodian_roots,
           allowed_custodians, revoked_custodians):
    def deny(reason): return _out(reason=reason)
    if (not isinstance(independently_pinned_manifest_hash,str)
        or not HEX.fullmatch(independently_pinned_manifest_hash)
        or not isinstance(expected_archive_head,str) or not HEX.fullmatch(expected_archive_head)
        or not isinstance(expected_requester,str) or not IDENT.fullmatch(expected_requester)
        or not isinstance(expected_nonce,str) or not HEX.fullmatch(expected_nonce)
        or type(trusted_current_epoch) is not int or trusted_current_epoch<1
        or not isinstance(consumed_nonces,(set,frozenset))
        or any(not isinstance(n,str) or not HEX.fullmatch(n) for n in consumed_nonces)):
        return deny("missing-independent-content-policy")
    try:
        digest=manifest_digest(manifest)
        canonical_challenge(challenge)
        payload=canonical_reply(response)
    except (ValueError,TypeError,OverflowError) as exc:
        return deny(str(exc))
    if digest!=independently_pinned_manifest_hash or manifest["archive_head_sha256"]!=expected_archive_head:
        return deny("content-manifest-pin-mismatch")
    if response["challenge"]!=challenge:
        return deny("content-response-challenge-mismatch")
    if (challenge["requester_id"]!=expected_requester
        or challenge["nonce_hex"]!=expected_nonce
        or challenge["manifest_sha256"]!=digest):
        return deny("content-challenge-binding-mismatch")
    if expected_nonce in consumed_nonces:
        return deny("content-challenge-replay")
    if not challenge["issued_epoch"]<=trusted_current_epoch<=challenge["expires_epoch"]:
        return deny("content-challenge-expired-or-future")
    index=challenge["chunk_index"]
    if index>=len(manifest["chunk_sha256"]):
        return deny("content-chunk-out-of-range")
    if (not isinstance(custodian_roots,dict)
        or not isinstance(allowed_custodians,(set,frozenset))
        or not isinstance(revoked_custodians,(set,frozenset))
        or any(not isinstance(key,str) or not HEX.fullmatch(key)
               for key in allowed_custodians|revoked_custodians)):
        return deny("missing-custodian-trust-policy")
    key=response["custodian_key_id"]
    if key in revoked_custodians: return deny("content-custodian-revoked")
    if key not in allowed_custodians: return deny("content-custodian-not-allowed")
    public=custodian_roots.get(key)
    if not isinstance(public,bytes) or len(public)!=32 or hashlib.sha256(public).hexdigest()!=key:
        return deny("untrusted-content-custodian")
    try:
        data=base64.b64decode(response["chunk_b64"],validate=True)
    except (ValueError,base64.binascii.Error):
        return deny("invalid-content-chunk-encoding")
    expected_length=(manifest["total_bytes"]-manifest["chunk_size"]*index
                     if index==len(manifest["chunk_sha256"])-1 else manifest["chunk_size"])
    if len(data)!=expected_length: return deny("content-chunk-length-mismatch")
    if hashlib.sha256(data).hexdigest()!=manifest["chunk_sha256"][index]:
        return deny("content-chunk-hash-mismatch")
    encoded=response["signature_b64"]
    if not isinstance(encoded,str) or len(encoded)>96:
        return deny("invalid-content-signature-format")
    try: signature=base64.b64decode(encoded,validate=True)
    except (ValueError,base64.binascii.Error):
        return deny("invalid-content-signature-format")
    if len(signature)!=64: return deny("invalid-content-signature-format")
    try: Ed25519PublicKey.from_public_bytes(public).verify(signature,DOMAIN+payload)
    except (InvalidSignature,ValueError): return deny("invalid-content-signature")
    return {**_out(),"content_sample_valid":True,"state":"pending-review",
            "reason":"authenticated-sampled-content-not-proof-of-durable-remote-storage",
            "chunk_index":index,"manifest_sha256":digest,"nonce_hex":expected_nonce}
