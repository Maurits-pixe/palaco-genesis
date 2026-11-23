#!/usr/bin/env python3
"""Offline handoff of a fully verified sampling checkpoint succession.

A trusted separately pinned manifest digest binds all signed revisions and
the intended recipient. The independent recipient acknowledgement asserts
receipt-for-review ONLY. No shipping, signing, storage or authority here.
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
    "palaco_sampling_succession_handoff_verify",
    Path(__file__).with_name("sampling_checkpoint_succession.py"))
succession=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(succession)

DOMAIN=b"PALACO-SAMPLING-SUCCESSION-HANDOFF-V1\x00"
RECEIPT_DOMAIN=b"PALACO-SAMPLING-SUCCESSION-RECEIPT-V1\x00"
PACKAGE_FIELDS={"schema_version","recipient_id","genesis_record_sha256",
                "latest_record_sha256","ledger_head_sha256","records"}
RECEIPT_FIELDS={"schema_version","recipient_id","package_sha256",
                "receipt_nonce_hex","disposition"}
ENVELOPE_FIELDS={"receipt","recipient_key_id","signature_b64"}
HEX=succession.signed.HEX
IDENT=succession.signed.IDENT
DISPOSITION="received-for-independent-review"
MAX_PACKAGE_BYTES=succession.MAX_RECORDS*succession.MAX_BYTES+4096


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def _out(**kw):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "state":"quarantined",**kw}


def valid_package(value):
    if not isinstance(value,dict) or set(value)!=PACKAGE_FIELDS:
        return False
    if value["schema_version"]!="0.1.0":
        return False
    if not isinstance(value["recipient_id"],str) or not IDENT.fullmatch(value["recipient_id"]):
        return False
    for field in ("genesis_record_sha256","latest_record_sha256","ledger_head_sha256"):
        if not isinstance(value[field],str) or not HEX.fullmatch(value[field]):
            return False
    records=value["records"]
    if not isinstance(records,list) or not 1<=len(records)<=succession.MAX_RECORDS:
        return False
    try:
        if len(canonical(value))>MAX_PACKAGE_BYTES:return False
        for i,item in enumerate(records,1):
            if not isinstance(item,dict) or set(item)!={"record"}:
                return False
            succession.canonical(item["record"])
            if item["record"]["revision"]!=i:
                return False
        return (succession.record_digest(records[0])==value["genesis_record_sha256"]
                and succession.record_digest(records[-1])==value["latest_record_sha256"])
    except (ValueError,TypeError,OverflowError):
        return False


def package_hash(value):
    return hashlib.sha256(DOMAIN+canonical(value)).hexdigest()


def prepare(db,records,witness_roots,witness_organizations,revoked_witnesses,
            required_organizations,trusted_genesis,trusted_head,
            minimum_revision,trusted_ledger_head,minimum_ledger_batches,
            recipient_id):
    def deny(reason): return _out(package_prepared=False,reason=reason)
    if not isinstance(recipient_id,str) or not IDENT.fullmatch(recipient_id):
        return deny("invalid-handoff-recipient")
    checked=succession.verify(
        db,records,witness_roots,witness_organizations,revoked_witnesses,
        required_organizations,trusted_genesis,trusted_head,minimum_revision,
        trusted_ledger_head,minimum_ledger_batches)
    if not checked["sampling_succession_valid"]:
        return deny(checked["reason"])
    try:
        package={"schema_version":"0.1.0","recipient_id":recipient_id,
                 "genesis_record_sha256":trusted_genesis,
                 "latest_record_sha256":trusted_head,
                 "ledger_head_sha256":trusted_ledger_head,
                 "records":json.loads(canonical(records))}
        if not valid_package(package):
            return deny("invalid-handoff-package")
        digest=package_hash(package)
    except (ValueError,TypeError,OverflowError):
        return deny("invalid-handoff-package")
    return _out(package_prepared=True,state="pending-review",
                reason="sampling-history-package-prepared-not-delivered",
                package=package,package_sha256=digest)


def canonical_receipt(body):
    if not isinstance(body,dict) or set(body)!=RECEIPT_FIELDS:
        raise ValueError("invalid-sampling-handoff-receipt-schema")
    if body["schema_version"]!="0.1.0" or body["disposition"]!=DISPOSITION:
        raise ValueError("invalid-sampling-handoff-disposition")
    if not isinstance(body["recipient_id"],str) or not IDENT.fullmatch(body["recipient_id"]):
        raise ValueError("invalid-sampling-handoff-receipt-recipient")
    for field in ("package_sha256","receipt_nonce_hex"):
        if not isinstance(body[field],str) or not HEX.fullmatch(body[field]):
            raise ValueError("invalid-sampling-handoff-receipt-digest")
    return canonical(body)


def verify_receipt(db,package,receipt,witness_roots,witness_organizations,
                   revoked_witnesses,required_organizations,trusted_genesis,
                   trusted_head,minimum_revision,trusted_ledger_head,
                   minimum_ledger_batches,expected_recipient,expected_package_hash,
                   expected_nonce,used_nonces,recipient_roots,allowed_recipients,
                   revoked_recipients):
    def deny(reason):return _out(receipt_valid=False,reason=reason)
    if (not isinstance(expected_recipient,str) or not IDENT.fullmatch(expected_recipient)
        or not isinstance(expected_package_hash,str) or not HEX.fullmatch(expected_package_hash)
        or not isinstance(expected_nonce,str) or not HEX.fullmatch(expected_nonce)
        or not isinstance(used_nonces,(set,frozenset))
        or any(not isinstance(x,str) or not HEX.fullmatch(x) for x in used_nonces)):
        return deny("missing-independent-handoff-policy")
    if not valid_package(package):return deny("invalid-handoff-package")
    if package["recipient_id"]!=expected_recipient:return deny("handoff-recipient-mismatch")
    if (package["genesis_record_sha256"]!=trusted_genesis
        or package["latest_record_sha256"]!=trusted_head
        or package["ledger_head_sha256"]!=trusted_ledger_head):
        return deny("handoff-history-pin-mismatch")
    if package_hash(package)!=expected_package_hash:
        return deny("handoff-package-pin-mismatch")
    if not isinstance(receipt,dict) or set(receipt)!=ENVELOPE_FIELDS:
        return deny("invalid-sampling-handoff-receipt-envelope")
    try:payload=canonical_receipt(receipt["receipt"])
    except (ValueError,TypeError,OverflowError) as exc:return deny(str(exc))
    body=receipt["receipt"]
    if (body["recipient_id"]!=expected_recipient
        or body["package_sha256"]!=expected_package_hash
        or body["receipt_nonce_hex"]!=expected_nonce):
        return deny("handoff-receipt-binding-mismatch")
    if expected_nonce in used_nonces:return deny("handoff-receipt-nonce-replayed")
    if (not isinstance(recipient_roots,dict)
        or not isinstance(allowed_recipients,(set,frozenset))
        or not isinstance(revoked_recipients,(set,frozenset))
        or any(not isinstance(k,str) or not HEX.fullmatch(k)
               for k in allowed_recipients|revoked_recipients)):
        return deny("missing-independent-recipient-trust")
    key=receipt["recipient_key_id"]
    if not isinstance(key,str) or not HEX.fullmatch(key):
        return deny("invalid-handoff-recipient-key")
    if key in witness_organizations:return deny("handoff-witness-recipient-key-collision")
    if key in revoked_recipients:return deny("handoff-recipient-revoked")
    if key not in allowed_recipients:return deny("handoff-recipient-not-allowed")
    pub=recipient_roots.get(key)
    if not isinstance(pub,bytes) or len(pub)!=32 or hashlib.sha256(pub).hexdigest()!=key:
        return deny("untrusted-handoff-recipient")
    encoded=receipt["signature_b64"]
    if not isinstance(encoded,str) or len(encoded)>96:return deny("invalid-handoff-signature-format")
    try:signature=base64.b64decode(encoded,validate=True)
    except (ValueError,base64.binascii.Error):return deny("invalid-handoff-signature-format")
    if len(signature)!=64:return deny("invalid-handoff-signature-format")
    try:Ed25519PublicKey.from_public_bytes(pub).verify(signature,RECEIPT_DOMAIN+payload)
    except (InvalidSignature,ValueError):return deny("invalid-handoff-signature")
    checked=succession.verify(
        db,package["records"],witness_roots,witness_organizations,
        revoked_witnesses,required_organizations,trusted_genesis,trusted_head,
        minimum_revision,trusted_ledger_head,minimum_ledger_batches)
    if not checked["sampling_succession_valid"]:
        return deny(checked["reason"])
    return _out(receipt_valid=True,state="pending-review",
                reason="authenticated-receipt-claim-not-proof-of-storage",
                recipient_key_id=key,receipt_nonce_hex=expected_nonce,
                package_sha256=expected_package_hash)
