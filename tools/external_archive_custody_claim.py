#!/usr/bin/env python3
"""Offline challenge-response verification for external archive custody claims.

The verifier accepts an independently issued nonce, archive pins, and an
Ed25519-signed custodian answer. No claim of actual storage availability,
legal independence, trusted clock, network delivery or release authority.
"""
import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec=importlib.util.spec_from_file_location(
    "palaco_external_custody_archive",
    Path(__file__).with_name("delegation_receipt_archive.py"))
archive=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(archive)

DOMAIN=b"PALACO-EXTERNAL-ARCHIVE-CUSTODY-CLAIM-V1\x00"
CHALLENGE_FIELDS={"schema_version","requester_id","nonce_hex","issued_epoch","expires_epoch",
                  "archive_head_sha256","archive_records","audit_head_sha256"}
RESPONSE_FIELDS={"challenge","custodian_key_id","custody_claim","signature_b64"}
NONCE=re.compile(r"^[0-9a-f]{64}$")
CLAIM="archive-available-for-independent-inspection"


def canonical_challenge(value):
    if not isinstance(value,dict) or set(value)!=CHALLENGE_FIELDS:
        raise ValueError("invalid-custody-challenge-schema")
    if value["schema_version"]!="0.1.0":
        raise ValueError("invalid-custody-challenge-version")
    if not isinstance(value["requester_id"],str) or not archive.IDENT.fullmatch(value["requester_id"]):
        raise ValueError("invalid-custody-requester")
    if not isinstance(value["nonce_hex"],str) or not NONCE.fullmatch(value["nonce_hex"]):
        raise ValueError("invalid-custody-nonce")
    for field in ("issued_epoch","expires_epoch","archive_records"):
        if type(value[field]) is not int or value[field]<1:
            raise ValueError("invalid-custody-counter")
    if value["issued_epoch"]>=value["expires_epoch"]:
        raise ValueError("invalid-custody-interval")
    if value["archive_records"]>archive.MAX_RECORDS:
        raise ValueError("invalid-custody-count")
    for field in ("archive_head_sha256","audit_head_sha256"):
        if not isinstance(value[field],str) or not archive.HEX.fullmatch(value[field]):
            raise ValueError("invalid-custody-hash")
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def canonical_response(response):
    if not isinstance(response,dict) or set(response)!=RESPONSE_FIELDS:
        raise ValueError("invalid-custody-response-schema")
    challenge=canonical_challenge(response["challenge"])
    if response["custody_claim"]!=CLAIM:
        raise ValueError("invalid-custody-claim")
    if not isinstance(response["custodian_key_id"],str) or not archive.HEX.fullmatch(response["custodian_key_id"]):
        raise ValueError("invalid-custody-custodian")
    return json.dumps({"challenge":json.loads(challenge),"custodian_key_id":response["custodian_key_id"],
                       "custody_claim":CLAIM},sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def _out(**kw):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "custody_claim_valid":False,"state":"quarantined",**kw}


def verify(db, records, witness_roots, witness_organizations, revoked_witnesses,
           minimum_witness_organizations, custodian_roots, custodian_organizations,
           revoked_custodians, allowed_custodians, trusted_archive_genesis,
           trusted_archive_head, minimum_archive_records, trusted_audit_head,
           minimum_receipts, challenge, response, expected_requester,
           expected_nonce, trusted_current_epoch, used_nonces):
    def deny(reason):return _out(reason=reason)
    if (not isinstance(expected_requester,str) or not archive.IDENT.fullmatch(expected_requester)
        or not isinstance(expected_nonce,str) or not NONCE.fullmatch(expected_nonce)
        or type(trusted_current_epoch) is not int or trusted_current_epoch<1
        or not isinstance(used_nonces,(set,frozenset))
        or any(not isinstance(n,str) or not NONCE.fullmatch(n) for n in used_nonces)):
        return deny("missing-independent-challenge-policy")
    try:
        canonical_challenge(challenge)
        payload=canonical_response(response)
    except (TypeError,ValueError,OverflowError) as exc:
        return deny(str(exc))
    if response["challenge"]!=challenge:
        return deny("custody-challenge-response-mismatch")
    if challenge["requester_id"]!=expected_requester or challenge["nonce_hex"]!=expected_nonce:
        return deny("custody-challenge-not-requested")
    if expected_nonce in used_nonces:
        return deny("custody-challenge-replay")
    if not challenge["issued_epoch"]<=trusted_current_epoch<=challenge["expires_epoch"]:
        return deny("custody-challenge-expired-or-future")
    if (challenge["archive_head_sha256"]!=trusted_archive_head
        or challenge["audit_head_sha256"]!=trusted_audit_head
        or challenge["archive_records"]!=len(records)):
        return deny("custody-challenge-archive-binding-mismatch")
    checked=archive.verify(
        db,records,witness_roots,witness_organizations,revoked_witnesses,
        minimum_witness_organizations,custodian_roots,custodian_organizations,
        revoked_custodians,allowed_custodians,trusted_archive_genesis,
        trusted_archive_head,minimum_archive_records,trusted_audit_head,
        minimum_receipts)
    if not checked["archive_valid"]:return deny(checked["reason"])
    signer=response["custodian_key_id"]
    last_signer=records[-1]["custodian_key_id"]
    if signer!=last_signer:return deny("custody-custodian-mismatch")
    if signer in revoked_custodians:return deny("archive-custodian-revoked")
    if signer not in allowed_custodians:return deny("archive-custodian-not-allowed")
    key=custodian_roots.get(signer)
    if not isinstance(key,bytes) or len(key)!=32 or hashlib.sha256(key).hexdigest()!=signer:
        return deny("untrusted-archive-custodian")
    encoded=response["signature_b64"]
    if not isinstance(encoded,str) or len(encoded)>96:
        return deny("invalid-custody-signature-format")
    try: signature=base64.b64decode(encoded,validate=True)
    except (ValueError,base64.binascii.Error):return deny("invalid-custody-signature-format")
    if len(signature)!=64:return deny("invalid-custody-signature-format")
    try: Ed25519PublicKey.from_public_bytes(key).verify(signature,DOMAIN+payload)
    except (InvalidSignature,ValueError):return deny("invalid-custody-signature")
    return {**_out(),"custody_claim_valid":True,"state":"pending-review",
            "reason":"signed-availability-claim-only-not-storage-proof",
            "archive_head_sha256":checked["head_hash"],
            "archive_records":checked["archive_records"],
            "nonce_hex":expected_nonce}
