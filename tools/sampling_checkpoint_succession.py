#!/usr/bin/env python3
"""Offline signed succession history for archived sampling-ledger checkpoints.

Every revision has a quorum of independently trusted Ed25519 witnesses,
matches a prefix of the locally verified ledger, and is bound into a
domain-separated SHA-256 record chain. External genesis/head/floor pins
and live revocations are caller-owned. Never authorize release.
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
    "palaco_sampling_succession_checkpoint",
    Path(__file__).with_name("signed_sampling_ledger_checkpoint.py"))
signed=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signed)

DOMAIN=b"PALACO-SAMPLING-CHECKPOINT-SUCCESSION-V1\x00"
GENESIS="0"*64
RECORD_FIELDS={"schema_version","revision","checkpoint","witnesses",
               "previous_record_sha256"}
MAX_RECORDS=128
MAX_BYTES=65536


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def canonical(record):
    if not isinstance(record,dict) or set(record)!=RECORD_FIELDS:
        raise ValueError("invalid-sampling-succession-record")
    if record["schema_version"]!="0.1.0":
        raise ValueError("invalid-sampling-succession-version")
    if type(record["revision"]) is not int or not 1<=record["revision"]<=MAX_RECORDS:
        raise ValueError("invalid-sampling-succession-revision")
    prior=record["previous_record_sha256"]
    if not isinstance(prior,str) or not signed.HEX.fullmatch(prior):
        raise ValueError("invalid-sampling-succession-predecessor")
    signed.canonical(record["checkpoint"])
    witnesses=record["witnesses"]
    if (not isinstance(witnesses,list)
        or not 2<=len(witnesses)<=signed.MAX_WITNESSES
        or any(not isinstance(e,dict) or set(e)!=signed.ENVELOPE_FIELDS
               for e in witnesses)):
        raise ValueError("invalid-sampling-succession-witnesses")
    raw=_json(record)
    if len(raw)>MAX_BYTES: raise ValueError("sampling-succession-record-too-large")
    return raw


def record_digest(envelope):
    return hashlib.sha256(DOMAIN+_json(envelope)).hexdigest()


def _out(**fields):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "sampling_succession_valid":False,"state":"quarantined",**fields}


def verify(db,records,witness_roots,witness_organizations,revoked_witnesses,
           required_organizations,trusted_genesis,trusted_head,
           minimum_revision,trusted_ledger_head,minimum_ledger_batches):
    def deny(reason): return _out(reason=reason)
    if (not isinstance(trusted_genesis,str) or not signed.HEX.fullmatch(trusted_genesis)
        or not isinstance(trusted_head,str) or not signed.HEX.fullmatch(trusted_head)
        or not isinstance(trusted_ledger_head,str) or not signed.HEX.fullmatch(trusted_ledger_head)
        or type(minimum_revision) is not int or not 1<=minimum_revision<=MAX_RECORDS
        or type(minimum_ledger_batches) is not int
        or not 1<=minimum_ledger_batches<=signed.ledger.MAX_BATCHES):
        return deny("missing-independent-succession-pins")
    if not isinstance(records,list) or not 1<=len(records)<=MAX_RECORDS:
        return deny("invalid-sampling-succession-length")
    if (not isinstance(witness_roots,dict)
        or not isinstance(witness_organizations,dict)
        or not isinstance(revoked_witnesses,(set,frozenset))
        or type(required_organizations) is not int
        or not 2<=required_organizations<=signed.MAX_WITNESSES):
        return deny("missing-independent-succession-witness-policy")
    if any(not isinstance(key,str) or not signed.HEX.fullmatch(key)
           for key in revoked_witnesses):
        return deny("invalid-succession-revocation-policy")
    for key,org in witness_organizations.items():
        if (not isinstance(key,str) or not signed.HEX.fullmatch(key)
            or not isinstance(org,str) or not signed.IDENT.fullmatch(org)):
            return deny("invalid-succession-organization-policy")
    if len({org for key,org in witness_organizations.items()
            if key not in revoked_witnesses})<required_organizations:
        return deny("insufficient-eligible-succession-organizations")
    try:
        path=signed.ledger._path(db)
        if not path.is_file():return deny("missing-sampling-ledger")
        conn=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            conn.execute("BEGIN")
            ledger=signed.ledger._scan(conn)
            if ledger is None or ledger["batches"]==0:
                return deny("sampling-ledger-integrity-failed")
            if ledger["batches"]<minimum_ledger_batches:
                return deny("sampling-ledger-rollback")
            if ledger["head_hash"]!=trusted_ledger_head:
                return deny("sampling-ledger-head-mismatch")
            snapshots={seq:(head,manifest,evidence)
                       for seq,head,manifest,evidence in conn.execute(
                "SELECT sequence,event_hash,manifest_sha256,evidence_sha256 FROM archive_sample_batches")}
        finally:
            conn.close()
    except (sqlite3.Error,ValueError,TypeError,OSError):
        return deny("unreadable-sampling-succession-ledger")

    previous=GENESIS
    previous_batch=0
    previous_keys=set()
    for revision,envelope in enumerate(records,1):
        if not isinstance(envelope,dict) or set(envelope)!={"record"}:
            return deny("invalid-sampling-succession-envelope")
        body=envelope["record"]
        try: canonical(body)
        except (TypeError,ValueError,OverflowError) as exc:return deny(str(exc))
        if body["revision"]!=revision:return deny("sampling-succession-revision-gap")
        if body["previous_record_sha256"]!=previous:
            return deny("sampling-succession-link-mismatch")
        cp=body["checkpoint"]
        batch=cp["batch_count"]
        if batch<=previous_batch:return deny("sampling-succession-batch-rollback")
        if snapshots.get(batch)!=(cp["ledger_head_sha256"],
                                  cp["latest_manifest_sha256"],
                                  cp["latest_evidence_sha256"]):
            return deny("sampling-succession-prefix-mismatch")
        seen_keys=set()
        seen_orgs=set()
        for statement in body["witnesses"]:
            key=statement["witness_key_id"]
            if not isinstance(key,str) or not signed.HEX.fullmatch(key):
                return deny("invalid-succession-witness-key")
            if key in seen_keys:return deny("duplicate-succession-witness")
            seen_keys.add(key)
            if key in revoked_witnesses:return deny("revoked-succession-witness")
            org=witness_organizations.get(key)
            if org is None:return deny("succession-witness-not-allowed")
            if org in seen_orgs:return deny("duplicate-succession-organization")
            seen_orgs.add(org)
            if key in previous_keys and key in revoked_witnesses:
                return deny("revoked-succession-witness")
            public=witness_roots.get(key)
            if not isinstance(public,bytes) or len(public)!=32 or hashlib.sha256(public).hexdigest()!=key:
                return deny("untrusted-succession-witness")
            try: payload=signed.canonical(statement["checkpoint"])
            except (ValueError,TypeError,OverflowError) as exc:return deny(str(exc))
            if statement["checkpoint"]!=cp:
                return deny("conflicting-succession-checkpoint")
            encoded=statement["signature_b64"]
            if not isinstance(encoded,str) or len(encoded)>96:
                return deny("invalid-succession-signature-format")
            try: signature=base64.b64decode(encoded,validate=True)
            except (ValueError,base64.binascii.Error):
                return deny("invalid-succession-signature-format")
            if len(signature)!=64:return deny("invalid-succession-signature-format")
            try: Ed25519PublicKey.from_public_bytes(public).verify(signature,signed.DOMAIN+payload)
            except (InvalidSignature,ValueError):
                return deny("invalid-succession-signature")
        if len(seen_orgs)<required_organizations:
            return deny("insufficient-distinct-succession-organizations")
        digest=record_digest(envelope)
        if revision==1 and digest!=trusted_genesis:
            return deny("untrusted-succession-genesis")
        previous=digest
        previous_batch=batch
        previous_keys|=seen_keys
    if len(records)<minimum_revision:return deny("sampling-succession-rollback")
    if previous!=trusted_head:return deny("sampling-succession-head-mismatch")
    if previous_batch!=ledger["batches"]:
        return deny("sampling-succession-latest-not-current")
    return {**_out(),"sampling_succession_valid":True,"state":"pending-review",
            "reason":"signed-sampling-succession-history-no-operational-authority",
            "revisions":len(records),"batch_count":previous_batch,
            "head_hash":previous}
