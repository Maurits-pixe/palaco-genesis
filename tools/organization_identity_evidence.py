#!/usr/bin/env python3
"""Detached organization-identity evidence bound to signed witness succession.

Cryptographic verification of an assessor's claim is NOT legal identity proof.
No external identity lookup, attestation issuance or authorization is performed.
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
    "palaco_org_evidence_succession",Path(__file__).with_name("witness_registry_succession.py"))
succession=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(succession)

DOMAIN=b"PALACO-ORG-IDENTITY-EVIDENCE-V1\x00"
FIELDS={"schema_version","organization_id","witness_key_id","registry_revision",
        "registry_envelope_sha256","evidence_sha256","assessment"}
ENVELOPE_FIELDS={"evidence","assessor_key_id","signature_b64"}
ASSESSMENT="reviewed-claim-no-legal-verification"
MAX_ASSESSMENTS=32
HEX=succession.registry.quorum.signed.chain.HEX


def canonical(body):
    if not isinstance(body,dict) or set(body)!=FIELDS:
        raise ValueError("invalid-identity-evidence-schema")
    if body["schema_version"]!="0.1.0" or body["assessment"]!=ASSESSMENT:
        raise ValueError("invalid-identity-assessment")
    org=body["organization_id"]
    if not isinstance(org,str) or not succession.registry.ORGANIZATION.fullmatch(org):
        raise ValueError("invalid-organization-id")
    if type(body["registry_revision"]) is not int or not 1<=body["registry_revision"]<=2147483647:
        raise ValueError("invalid-identity-evidence-revision")
    for name in ("witness_key_id","registry_envelope_sha256","evidence_sha256"):
        if not isinstance(body[name],str) or not HEX.fullmatch(body[name]):
            raise ValueError("invalid-identity-evidence-digest")
    return json.dumps(body,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def _result(**kw):
    return {"release_gate":"HOLD","authorization_granted":False,
            "recovery_approved":False,"automatic_restore":False,
            "identity_evidence_valid":False,"state":"quarantined",**kw}


def verify(snapshots, records, signed_evidence, issuer_roots, revoked_issuers,
           assessor_roots, revoked_assessors, allowed_assessors,
           trusted_genesis_digest, trusted_latest_record_digest,
           minimum_registry_revision):
    def deny(reason):
        return _result(reason=reason)
    if (not isinstance(assessor_roots,dict) or not isinstance(revoked_assessors,(set,frozenset))
        or not isinstance(allowed_assessors,(set,frozenset))
        or any(not isinstance(x,str) or not HEX.fullmatch(x)
               for x in revoked_assessors|allowed_assessors)):
        return deny("missing-independent-assessor-policy")
    history=succession.verify(snapshots,records,issuer_roots,revoked_issuers,
                             trusted_genesis_digest,trusted_latest_record_digest,
                             minimum_registry_revision)
    if not history["succession_valid"]:
        return deny(history["reason"])
    if not isinstance(signed_evidence,dict) or set(signed_evidence)!=ENVELOPE_FIELDS:
        return deny("invalid-identity-evidence-envelope")
    try:
        payload=canonical(signed_evidence["evidence"])
    except (ValueError,TypeError,OverflowError) as exc:
        return deny(str(exc))
    body=signed_evidence["evidence"]
    current=snapshots[-1]
    if (body["registry_revision"]!=current["registry"]["revision"]
        or body["registry_envelope_sha256"]!=succession.digest(current)):
        return deny("stale-identity-evidence-binding")
    active=[entry for entry in current["registry"]["witnesses"]
            if entry["organization_id"]==body["organization_id"] and entry["status"]=="active"]
    if len(active)!=1 or active[0]["witness_key_id"]!=body["witness_key_id"]:
        return deny("identity-evidence-witness-mismatch")
    signer=signed_evidence["assessor_key_id"]
    if not isinstance(signer,str) or not HEX.fullmatch(signer):
        return deny("invalid-assessor-id")
    if signer in revoked_assessors:
        return deny("assessor-revoked")
    if signer not in allowed_assessors:
        return deny("assessor-not-allowed")
    if signer==current["issuer_key_id"] or signer in {
        e["witness_key_id"] for e in current["registry"]["witnesses"]}:
        return deny("assessor-role-collision")
    pub=assessor_roots.get(signer)
    if not isinstance(pub,bytes) or len(pub)!=32 or hashlib.sha256(pub).hexdigest()!=signer:
        return deny("untrusted-assessor")
    text=signed_evidence["signature_b64"]
    if not isinstance(text,str) or len(text)>96:
        return deny("invalid-assessor-signature-format")
    try:
        sig=base64.b64decode(text,validate=True)
        if len(sig)!=64:
            return deny("invalid-assessor-signature-format")
        Ed25519PublicKey.from_public_bytes(pub).verify(sig,DOMAIN+payload)
    except (InvalidSignature,ValueError,base64.binascii.Error):
        return deny("invalid-assessor-signature")
    return {**_result(),"identity_evidence_valid":True,"state":"pending-review",
            "reason":"authenticated-assessor-claim-no-legal-identity-proof",
            "organization_id":body["organization_id"],
            "registry_revision":body["registry_revision"]}
