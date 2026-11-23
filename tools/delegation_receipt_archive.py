#!/usr/bin/env python3
"""Verify independently signed, hash-linked offline archive declarations.

Records attest checkpoints but do NOT establish actual off-device custody.
All signer roots, organizational membership, revocations and genesis/head
pins MUST arrive independently of the archive under review.
"""
import base64
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_spec=importlib.util.spec_from_file_location(
    "palaco_archive_receipt_checkpoint",
    Path(__file__).with_name("signed_delegation_receipt_audit_anchor.py"))
checkpoint=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checkpoint)

DOMAIN=b"PALACO-RECEIPT-CHECKPOINT-ARCHIVE-V1\x00"
HASH_DOMAIN=b"PALACO-RECEIPT-ARCHIVE-RECORD-V1\x00"
ZERO="0"*64
FIELDS={"schema_version","sequence","checkpoint","witnesses","previous_record_sha256"}
ENVELOPE={"archive","custodian_key_id","signature_b64"}
MAX_RECORDS=128
MAX_BYTES=65536
HEX=checkpoint.audit.HEX
IDENT=checkpoint.audit.IDENT


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def canonical(value):
    if not isinstance(value,dict) or set(value)!=FIELDS:
        raise ValueError("invalid-archive-record-schema")
    if value["schema_version"]!="0.1.0":
        raise ValueError("invalid-archive-version")
    if type(value["sequence"]) is not int or not 1<=value["sequence"]<=MAX_RECORDS:
        raise ValueError("invalid-archive-sequence")
    for name in ("previous_record_sha256",):
        if not isinstance(value[name],str) or not HEX.fullmatch(value[name]):
            raise ValueError("invalid-archive-digest")
    checkpoint.canonical(value["checkpoint"])
    witnesses=value["witnesses"]
    if not isinstance(witnesses,list) or not 2<=len(witnesses)<=checkpoint.MAX_WITNESSES:
        raise ValueError("invalid-archive-witnesses")
    if any(not isinstance(e,dict) or set(e)!=checkpoint.ENVELOPE_FIELDS
           for e in witnesses):
        raise ValueError("invalid-archive-witness-envelope")
    raw=_json(value)
    if len(raw)>MAX_BYTES:
        raise ValueError("archive-record-too-large")
    return raw


def record_digest(envelope):
    return hashlib.sha256(HASH_DOMAIN+_json(envelope)).hexdigest()


def _out(**fields):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "archive_valid":False,"state":"quarantined",**fields}


def verify(db, archive, witness_roots, witness_organizations, revoked_witnesses,
           minimum_witness_organizations, custodian_roots, custodian_organizations,
           revoked_custodians, allowed_custodians,
           trusted_genesis_record_hash, trusted_latest_record_hash,
           minimum_archive_records, independently_pinned_audit_head,
           minimum_receipt_events):
    def deny(reason): return _out(reason=reason)
    if (not isinstance(trusted_genesis_record_hash,str) or not HEX.fullmatch(trusted_genesis_record_hash)
        or not isinstance(trusted_latest_record_hash,str) or not HEX.fullmatch(trusted_latest_record_hash)
        or not isinstance(independently_pinned_audit_head,str) or not HEX.fullmatch(independently_pinned_audit_head)
        or type(minimum_archive_records) is not int or not 1<=minimum_archive_records<=MAX_RECORDS
        or type(minimum_receipt_events) is not int or not 1<=minimum_receipt_events<=checkpoint.audit.MAX_EVENTS):
        return deny("missing-independent-archive-pins")
    if (not isinstance(archive,list) or not 1<=len(archive)<=MAX_RECORDS):
        return deny("invalid-archive-length")
    if (not isinstance(witness_roots,dict) or not isinstance(witness_organizations,dict)
        or not isinstance(revoked_witnesses,(set,frozenset))
        or type(minimum_witness_organizations) is not int or not 2<=minimum_witness_organizations<=checkpoint.MAX_WITNESSES
        or not isinstance(custodian_roots,dict) or not isinstance(custodian_organizations,dict)
        or not isinstance(revoked_custodians,(set,frozenset))
        or not isinstance(allowed_custodians,(set,frozenset))):
        return deny("missing-independent-archive-policy")
    if any(not isinstance(k,str) or not HEX.fullmatch(k)
           for k in revoked_witnesses|revoked_custodians|allowed_custodians):
        return deny("invalid-archive-key-policy")
    for roster in (witness_organizations,custodian_organizations):
        if any(not isinstance(k,str) or not HEX.fullmatch(k)
               or not isinstance(org,str) or not IDENT.fullmatch(org)
               for k,org in roster.items()):
            return deny("invalid-archive-organization-policy")
    eligible={org for key,org in witness_organizations.items() if key not in revoked_witnesses}
    if len(eligible)<minimum_witness_organizations:
        return deny("insufficient-archive-witness-organizations")
    checked=checkpoint.audit.inspect(db,independently_pinned_audit_head,minimum_receipt_events)
    if not checked["chain_valid"]: return deny(checked["reason"])
    try:
        conn=sqlite3.connect(Path(db).resolve().as_uri()+"?mode=ro",uri=True)
        try:
            prefix=dict(conn.execute("SELECT sequence,event_hash FROM delegation_receipt_audit"))
            recipient_keys={row[0] for row in conn.execute(
                "SELECT recipient_key_id FROM delegation_handoff_receipts")}
        finally:
            conn.close()
    except (sqlite3.Error,ValueError,OSError,TypeError):
        return deny("unreadable-archive-prefixes")
    if len(prefix)!=checked["entries"]:
        return deny("archive-prefix-integrity-failed")
    predecessor=ZERO
    last_count=0
    observed_custodian=None
    for step,envelope in enumerate(archive,1):
        if not isinstance(envelope,dict) or set(envelope)!=ENVELOPE:
            return deny("invalid-archive-envelope")
        try: raw=canonical(envelope["archive"])
        except (ValueError,TypeError,OverflowError) as exc: return deny(str(exc))
        body=envelope["archive"]
        if body["sequence"]!=step: return deny("archive-sequence-gap")
        if body["previous_record_sha256"]!=predecessor:
            return deny("archive-link-mismatch")
        cp=body["checkpoint"]
        count=cp["entries"]
        if count<=last_count: return deny("archive-count-not-increasing")
        if prefix.get(count)!=cp["audit_head_sha256"]:
            return deny("archive-prefix-mismatch")
        if step==1 and record_digest(envelope)!=trusted_genesis_record_hash:
            return deny("untrusted-archive-genesis")
        custodian=envelope["custodian_key_id"]
        if not isinstance(custodian,str) or not HEX.fullmatch(custodian):
            return deny("invalid-archive-custodian-key")
        if custodian in revoked_custodians: return deny("archive-custodian-revoked")
        if custodian not in allowed_custodians or custodian not in custodian_organizations:
            return deny("archive-custodian-not-allowed")
        if custodian in recipient_keys or custodian in witness_organizations:
            return deny("archive-custodian-role-collision")
        org=custodian_organizations[custodian]
        if org in eligible: return deny("archive-organization-role-collision")
        pub=custodian_roots.get(custodian)
        if not isinstance(pub,bytes) or len(pub)!=32 or hashlib.sha256(pub).hexdigest()!=custodian:
            return deny("untrusted-archive-custodian")
        encoded=envelope["signature_b64"]
        if not isinstance(encoded,str) or len(encoded)>96:
            return deny("invalid-archive-signature-format")
        try: sig=base64.b64decode(encoded,validate=True)
        except (ValueError,base64.binascii.Error): return deny("invalid-archive-signature-format")
        if len(sig)!=64: return deny("invalid-archive-signature-format")
        try: Ed25519PublicKey.from_public_bytes(pub).verify(sig,DOMAIN+raw)
        except (InvalidSignature,ValueError): return deny("invalid-archive-signature")
        if observed_custodian is not None and observed_custodian!=org:
            return deny("archive-custodian-organization-changed")
        observed_custodian=org
        seen_keys=set()
        seen_orgs=set()
        for w in body["witnesses"]:
            key=w["witness_key_id"]
            if not isinstance(key,str) or not HEX.fullmatch(key):
                return deny("invalid-archived-witness-key")
            if key in seen_keys: return deny("duplicate-archived-witness")
            seen_keys.add(key)
            if key in revoked_witnesses: return deny("archived-witness-revoked")
            organization=witness_organizations.get(key)
            if organization is None: return deny("archived-witness-not-allowed")
            if organization in seen_orgs: return deny("duplicate-archived-organization")
            seen_orgs.add(organization)
            if key in recipient_keys or key in custodian_organizations:
                return deny("archived-witness-role-collision")
            try: payload=checkpoint.canonical(w["checkpoint"])
            except (ValueError,TypeError,OverflowError) as exc: return deny(str(exc))
            if w["checkpoint"]!=cp: return deny("conflicting-archived-checkpoint")
            public=witness_roots.get(key)
            if not isinstance(public,bytes) or len(public)!=32 or hashlib.sha256(public).hexdigest()!=key:
                return deny("untrusted-archived-witness")
            b64=w["signature_b64"]
            if not isinstance(b64,str) or len(b64)>96:
                return deny("invalid-archived-signature-format")
            try: signature=base64.b64decode(b64,validate=True)
            except (ValueError,base64.binascii.Error): return deny("invalid-archived-signature-format")
            if len(signature)!=64: return deny("invalid-archived-signature-format")
            try: Ed25519PublicKey.from_public_bytes(public).verify(signature,checkpoint.DOMAIN+payload)
            except (InvalidSignature,ValueError): return deny("invalid-archived-signature")
        if len(seen_orgs)<minimum_witness_organizations:
            return deny("insufficient-archived-witness-organizations")
        predecessor=record_digest(envelope)
        last_count=count
    if len(archive)<minimum_archive_records: return deny("archive-rollback")
    if predecessor!=trusted_latest_record_hash: return deny("archive-head-mismatch")
    if last_count!=checked["entries"]: return deny("archive-latest-not-current")
    latest=checkpoint.verify(db,archive[-1]["archive"]["witnesses"],
                             witness_roots,witness_organizations,
                             revoked_witnesses,minimum_witness_organizations,
                             independently_pinned_audit_head,minimum_receipt_events)
    if not latest["witnessed_audit_valid"]: return deny(latest["reason"])
    return {**_out(),"archive_valid":True,"state":"pending-review",
            "reason":"verified-archive-claims-not-proof-of-independent-storage",
            "archive_records":len(archive),"receipt_events":last_count,
            "head_hash":predecessor}
