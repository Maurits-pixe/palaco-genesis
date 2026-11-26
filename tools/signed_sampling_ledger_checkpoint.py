#!/usr/bin/env python3
"""Read-only multi-organization Ed25519 checkpoint over archive sampling ledger.

Independently pinned ledger head/count, trust roots, organization roster and
current revocations are mandatory. Never sign, deploy, restore or authorize.
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
    "palaco_signed_sampling_ledger_source",
    Path(__file__).with_name("archive_sampling_evidence_ledger.py"))
ledger=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)

DOMAIN=b"PALACO-SIGNED-ARCHIVE-SAMPLING-LEDGER-V1\x00"
FIELDS={"schema_version","ledger_head_sha256","batch_count",
        "latest_manifest_sha256","latest_evidence_sha256"}
ENVELOPE_FIELDS={"checkpoint","witness_key_id","signature_b64"}
HEX=ledger.sampling.single.HEX
IDENT=ledger.sampling.single.IDENT
MAX_WITNESSES=16


def canonical(body):
    if not isinstance(body,dict) or set(body)!=FIELDS:
        raise ValueError("invalid-sampling-checkpoint-schema")
    if body["schema_version"]!="0.1.0":
        raise ValueError("invalid-sampling-checkpoint-version")
    if type(body["batch_count"]) is not int or not 1<=body["batch_count"]<=ledger.MAX_BATCHES:
        raise ValueError("invalid-sampling-checkpoint-count")
    for field in ("ledger_head_sha256","latest_manifest_sha256","latest_evidence_sha256"):
        if not isinstance(body[field],str) or not HEX.fullmatch(body[field]):
            raise ValueError("invalid-sampling-checkpoint-digest")
    return json.dumps(body,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def _out(**fields):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "sampling_checkpoint_valid":False,"state":"quarantined",**fields}


def verify(db,envelopes,witness_roots,witness_organizations,
           revoked_witnesses,required_organizations,
           independently_pinned_head,minimum_batches):
    def deny(reason):return _out(reason=reason)
    if (not isinstance(independently_pinned_head,str)
        or not HEX.fullmatch(independently_pinned_head)
        or type(minimum_batches) is not int
        or not 1<=minimum_batches<=ledger.MAX_BATCHES):
        return deny("missing-independent-sampling-checkpoint-pin")
    if (not isinstance(witness_roots,dict)
        or not isinstance(witness_organizations,dict)
        or not isinstance(revoked_witnesses,(set,frozenset))
        or type(required_organizations) is not int
        or not 2<=required_organizations<=MAX_WITNESSES):
        return deny("missing-independent-sampling-witness-policy")
    if any(not isinstance(key,str) or not HEX.fullmatch(key) for key in revoked_witnesses):
        return deny("invalid-sampling-witness-revocations")
    for key,org in witness_organizations.items():
        if (not isinstance(key,str) or not HEX.fullmatch(key)
            or not isinstance(org,str) or not IDENT.fullmatch(org)):
            return deny("invalid-sampling-witness-organization")
    eligible={org for key,org in witness_organizations.items() if key not in revoked_witnesses}
    if len(eligible)<required_organizations:
        return deny("insufficient-eligible-sampling-organizations")
    if (not isinstance(envelopes,list)
        or not required_organizations<=len(envelopes)<=MAX_WITNESSES):
        return deny("invalid-sampling-witness-count")
    try:
        target=ledger._path(db)
        if not target.is_file():
            return deny("missing-sampling-ledger")
        connection=sqlite3.connect(target.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            connection.execute("BEGIN")
            checked=ledger._scan(connection)
            if checked is None or checked["batches"]==0:
                return deny("sampling-ledger-integrity-failed")
            if checked["batches"]<minimum_batches:
                return deny("sampling-ledger-rollback")
            if checked["head_hash"]!=independently_pinned_head:
                return deny("sampling-ledger-head-mismatch")
            latest=connection.execute(
                "SELECT manifest_sha256,evidence_sha256 FROM archive_sample_batches WHERE sequence=?",
                (checked["batches"],)).fetchone()
            if latest is None:
                return deny("sampling-ledger-integrity-failed")
            expected={"schema_version":"0.1.0",
                      "ledger_head_sha256":checked["head_hash"],
                      "batch_count":checked["batches"],
                      "latest_manifest_sha256":latest[0],
                      "latest_evidence_sha256":latest[1]}
        finally:
            connection.close()
    except (sqlite3.Error,ValueError,TypeError,OSError):
        return deny("unreadable-sampling-checkpoint-ledger")
    seen_keys=set()
    seen_orgs=set()
    for envelope in envelopes:
        if not isinstance(envelope,dict) or set(envelope)!=ENVELOPE_FIELDS:
            return deny("invalid-sampling-witness-envelope")
        try: payload=canonical(envelope["checkpoint"])
        except (ValueError,TypeError,OverflowError) as exc:
            return deny(str(exc))
        key=envelope["witness_key_id"]
        if not isinstance(key,str) or not HEX.fullmatch(key):
            return deny("invalid-sampling-witness-key")
        if key in seen_keys:return deny("duplicate-sampling-witness")
        seen_keys.add(key)
        if key in revoked_witnesses:return deny("revoked-sampling-witness")
        org=witness_organizations.get(key)
        if org is None:return deny("sampling-witness-not-allowed")
        if org in seen_orgs:return deny("duplicate-sampling-witness-organization")
        seen_orgs.add(org)
        public=witness_roots.get(key)
        if not isinstance(public,bytes) or len(public)!=32 or hashlib.sha256(public).hexdigest()!=key:
            return deny("untrusted-sampling-witness")
        encoded=envelope["signature_b64"]
        if not isinstance(encoded,str) or len(encoded)>96:
            return deny("invalid-sampling-witness-signature-format")
        try: signature=base64.b64decode(encoded,validate=True)
        except (ValueError,base64.binascii.Error):
            return deny("invalid-sampling-witness-signature-format")
        if len(signature)!=64:return deny("invalid-sampling-witness-signature-format")
        try: Ed25519PublicKey.from_public_bytes(public).verify(signature,DOMAIN+payload)
        except (InvalidSignature,ValueError):
            return deny("invalid-sampling-witness-signature")
        if envelope["checkpoint"]!=expected:
            return deny("conflicting-sampling-checkpoint")
    if len(seen_orgs)<required_organizations:
        return deny("insufficient-distinct-sampling-organizations")
    return {**_out(),"sampling_checkpoint_valid":True,"state":"pending-review",
            "reason":"signed-sampling-ledger-evidence-only-no-authorization",
            "organizations":len(seen_orgs),"batch_count":checked["batches"],
            "head_hash":checked["head_hash"]}
