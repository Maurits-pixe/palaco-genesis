#!/usr/bin/env python3
"""Offline verification of successive governance-signed witness registries.

Each revision names its predecessor's exact signed envelope digest in a
separate succession wrapper. The first revision must match an independently
pinned genesis digest. Revocations are monotonic; key replacements may not
reuse revoked fingerprints. This is not a legal identity attestation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

_spec = importlib.util.spec_from_file_location(
    "palaco_witness_registry_source",Path(__file__).with_name("custody_witness_registry.py"))
registry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(registry)

DOMAIN = b"PALACO-WITNESS-REGISTRY-SUCCESSION-V1\x00"
SNAPSHOT_DOMAIN = b"PALACO-WITNESS-REGISTRY-SNAPSHOT-V1\x00"
FIELDS = {"schema_version", "revision", "registry_envelope_sha256",
          "previous_record_sha256"}
RECORD_FIELDS = {"succession", "issuer_key_id", "signature_b64"}
GENESIS = "0"*64
MAX_STEPS = 128


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(envelope):
    return hashlib.sha256(SNAPSHOT_DOMAIN + canonical(envelope)).hexdigest()


def canonical_succession(body):
    if not isinstance(body,dict) or set(body)!=FIELDS:
        raise ValueError("invalid-succession-schema")
    if body["schema_version"]!="0.1.0":
        raise ValueError("invalid-succession-version")
    if type(body["revision"]) is not int or not 1<=body["revision"]<=2147483647:
        raise ValueError("invalid-succession-revision")
    for field in ("registry_envelope_sha256","previous_record_sha256"):
        if not isinstance(body[field],str) or not registry.quorum.signed.chain.HEX.fullmatch(body[field]):
            raise ValueError("invalid-succession-digest")
    return canonical(body)


def record_digest(record):
    return hashlib.sha256(DOMAIN + canonical(record)).hexdigest()


def _base(**kw):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "succession_valid":False,"state":"quarantined",**kw}


def _signature(envelope, payload, issuer_roots, revoked):
    key_id=envelope.get("issuer_key_id")
    hexpat=registry.quorum.signed.chain.HEX
    if not isinstance(key_id,str) or not hexpat.fullmatch(key_id):
        return "invalid-succession-issuer"
    if key_id in revoked:
        return "succession-issuer-revoked"
    public=issuer_roots.get(key_id)
    if not isinstance(public,bytes) or len(public)!=32 or hashlib.sha256(public).hexdigest()!=key_id:
        return "untrusted-succession-issuer"
    text=envelope.get("signature_b64")
    if not isinstance(text,str) or len(text)>96:
        return "invalid-succession-signature-format"
    try:
        sig=base64.b64decode(text,validate=True)
        if len(sig)!=64:
            return "invalid-succession-signature-format"
        Ed25519PublicKey.from_public_bytes(public).verify(sig, DOMAIN+payload)
    except (InvalidSignature,ValueError,base64.binascii.Error):
        return "invalid-succession-signature"
    return None


def verify(snapshots, succession_records, issuer_roots, revoked_issuers,
           trusted_genesis_digest, trusted_latest_record_digest,
           minimum_revision):
    def deny(reason):
        return _base(reason=reason)
    hexpat=registry.quorum.signed.chain.HEX
    if (not isinstance(issuer_roots,dict) or not isinstance(revoked_issuers,(set,frozenset))
        or any(not isinstance(x,str) or not hexpat.fullmatch(x) for x in revoked_issuers)):
        return deny("missing-issuer-trust-policy")
    if (not isinstance(trusted_genesis_digest,str) or not hexpat.fullmatch(trusted_genesis_digest)
        or not isinstance(trusted_latest_record_digest,str)
        or not hexpat.fullmatch(trusted_latest_record_digest)
        or type(minimum_revision) is not int or minimum_revision<1):
        return deny("missing-independent-history-anchor")
    if (not isinstance(snapshots,list) or not isinstance(succession_records,list)
        or not 1<=len(snapshots)==len(succession_records)<=MAX_STEPS):
        return deny("invalid-history-length")
    previous_record=GENESIS
    previous_revision=None
    revoked_keys=set()
    known_organizations={}
    old_active={}
    for index,(snapshot,record) in enumerate(zip(snapshots,succession_records)):
        if not isinstance(snapshot,dict) or set(snapshot)!=registry.ENVELOPE_FIELDS:
            return deny("invalid-registry-envelope")
        try:
            regbytes=registry.canonical_registry(snapshot["registry"])
        except (TypeError,ValueError,OverflowError) as exc:
            return deny(str(exc))
        reg=snapshot["registry"]
        issuer=snapshot["issuer_key_id"]
        if issuer in revoked_issuers:
            return deny("registry-issuer-revoked")
        pub=issuer_roots.get(issuer)
        if not isinstance(pub,bytes) or len(pub)!=32 or hashlib.sha256(pub).hexdigest()!=issuer:
            return deny("untrusted-registry-issuer")
        try:
            signature=base64.b64decode(snapshot["signature_b64"],validate=True)
            if len(signature)!=64: raise ValueError("length")
            Ed25519PublicKey.from_public_bytes(pub).verify(signature,registry.DOMAIN+regbytes)
        except (InvalidSignature,ValueError,TypeError,base64.binascii.Error):
            return deny("invalid-registry-signature")
        if not isinstance(record,dict) or set(record)!=RECORD_FIELDS:
            return deny("invalid-succession-envelope")
        try:
            payload=canonical_succession(record["succession"])
        except (TypeError,ValueError,OverflowError) as exc:
            return deny(str(exc))
        step=record["succession"]
        if record["issuer_key_id"]!=issuer:
            return deny("succession-signer-mismatch")
        error=_signature(record,payload,issuer_roots,revoked_issuers)
        if error: return deny(error)
        if step["revision"]!=reg["revision"]:
            return deny("succession-revision-mismatch")
        if (previous_revision is not None and reg["revision"]!=previous_revision+1):
            return deny("missing-intermediate-revision")
        if step["registry_envelope_sha256"]!=digest(snapshot):
            return deny("registry-succession-binding-mismatch")
        if step["previous_record_sha256"]!=previous_record:
            return deny("succession-link-mismatch")
        if index==0 and digest(snapshot)!=trusted_genesis_digest:
            return deny("untrusted-history-genesis")
        current={row["witness_key_id"]:row for row in reg["witnesses"]}
        # Every prior key retains its organization and cannot silently disappear
        # or revert from revoked to active.
        for key,org in known_organizations.items():
            if key not in current or current[key]["organization_id"]!=org:
                return deny("witness-key-history-rewritten")
            if key in revoked_keys and current[key]["status"]!="revoked":
                return deny("revoked-key-resurrected")
        for key,row in current.items():
            if key in known_organizations and known_organizations[key]!=row["organization_id"]:
                return deny("witness-organization-reassigned")
            known_organizations[key]=row["organization_id"]
            if row["status"]=="revoked": revoked_keys.add(key)
        new_active={row["organization_id"]:key for key,row in current.items()
                    if row["status"]=="active"}
        for org,old_key in old_active.items():
            if org in new_active and new_active[org]!=old_key and current[old_key]["status"]!="revoked":
                return deny("rotation-without-revocation")
        old_active=new_active
        previous_revision=reg["revision"]
        previous_record=record_digest(record)
    if previous_revision<minimum_revision:
        return deny("registry-history-rollback")
    if previous_record!=trusted_latest_record_digest:
        return deny("registry-history-head-mismatch")
    return {**_base(),"succession_valid":True,"state":"pending-review",
            "reason":"signed-registry-succession-matches-independent-pins",
            "latest_revision":previous_revision,"steps":len(snapshots),
            "head_hash":previous_record}
