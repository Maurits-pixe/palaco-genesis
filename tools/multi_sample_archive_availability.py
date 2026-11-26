#!/usr/bin/env python3
"""Verify an independently seeded, non-repeating batch of archive chunk samples.

Pure offline verifier. The independent verifier must generate and pin a fresh
unpredictable 256-bit seed AFTER pinning the manifest, and separately preserve
consumed nonces. No challenge generation service, trust time or remote storage.
"""
import hashlib
import importlib.util
from pathlib import Path

_spec=importlib.util.spec_from_file_location(
    "palaco_single_archive_sample",Path(__file__).with_name("archive_content_availability.py"))
single=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(single)

SELECT_DOMAIN=b"PALACO-MULTISAMPLE-CHUNK-SELECT-V1\x00"
NONCE_DOMAIN=b"PALACO-MULTISAMPLE-CHALLENGE-NONCE-V1\x00"
MAX_SAMPLES=64


def _out(**fields):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "multi_sample_valid":False,"state":"quarantined",**fields}


def indices(seed_hex, manifest_sha256, population, count):
    """Domain-separated deterministic selection WITHOUT modulo bias or replacement."""
    if (not isinstance(seed_hex,str) or not single.HEX.fullmatch(seed_hex)
        or not isinstance(manifest_sha256,str) or not single.HEX.fullmatch(manifest_sha256)
        or type(population) is not int or not 1<=population<=single.MAX_CHUNKS
        or type(count) is not int or not 1<=count<=min(MAX_SAMPLES,population)):
        raise ValueError("invalid-multi-sample-selection-policy")
    seed=bytes.fromhex(seed_hex)+bytes.fromhex(manifest_sha256)
    available=list(range(population))
    selected=[]
    counter=0
    while len(selected)<count:
        remaining=len(available)
        boundary=(1<<256)-((1<<256)%remaining)
        while True:
            material=hashlib.sha256(SELECT_DOMAIN+seed+counter.to_bytes(8,"big")).digest()
            counter+=1
            value=int.from_bytes(material,"big")
            if value<boundary:
                break
        selected.append(available.pop(value%remaining))
    return selected


def nonce(seed_hex, manifest_sha256, ordinal):
    if (not isinstance(seed_hex,str) or not single.HEX.fullmatch(seed_hex)
        or not isinstance(manifest_sha256,str) or not single.HEX.fullmatch(manifest_sha256)
        or type(ordinal) is not int or not 0<=ordinal<MAX_SAMPLES):
        raise ValueError("invalid-multi-sample-nonce-policy")
    return hashlib.sha256(NONCE_DOMAIN+bytes.fromhex(seed_hex)+
                          bytes.fromhex(manifest_sha256)+ordinal.to_bytes(2,"big")).hexdigest()


def verify(manifest, pinned_manifest_hash, expected_archive_head, seed_hex,
           requested_sample_count, minimum_coverage_ppm, challenges, replies,
           expected_requester, trusted_current_epoch, consumed_nonces,
           custodian_roots, allowed_custodians, revoked_custodians):
    def deny(reason): return _out(reason=reason)
    if (type(minimum_coverage_ppm) is not int or not 1<=minimum_coverage_ppm<=1000000
        or not isinstance(consumed_nonces,(set,frozenset))
        or any(not isinstance(n,str) or not single.HEX.fullmatch(n) for n in consumed_nonces)):
        return deny("missing-independent-multi-sample-policy")
    try:
        manifest_sha=single.manifest_digest(manifest)
        chosen=indices(seed_hex,manifest_sha,len(manifest["chunk_sha256"]),requested_sample_count)
    except (ValueError,TypeError,OverflowError) as exc:
        return deny(str(exc))
    if manifest_sha!=pinned_manifest_hash or manifest["archive_head_sha256"]!=expected_archive_head:
        return deny("multi-sample-manifest-pin-mismatch")
    coverage=(len(chosen)*1000000)//len(manifest["chunk_sha256"])
    if coverage<minimum_coverage_ppm:
        return deny("insufficient-multi-sample-coverage")
    if (not isinstance(challenges,list) or not isinstance(replies,list)
        or len(challenges)!=len(chosen) or len(replies)!=len(chosen)):
        return deny("incomplete-multi-sample-batch")
    used=set(consumed_nonces)
    signer=None
    for ordinal,idx in enumerate(chosen):
        request=challenges[ordinal]
        reply=replies[ordinal]
        try:
            expected_nonce=nonce(seed_hex,manifest_sha,ordinal)
            if not isinstance(request,dict) or request.get("chunk_index")!=idx:
                return deny("multi-sample-index-mismatch")
            if request.get("nonce_hex")!=expected_nonce:
                return deny("multi-sample-nonce-mismatch")
            if not isinstance(reply,dict) or not isinstance(reply.get("custodian_key_id"),str):
                return deny("invalid-multi-sample-reply")
            if signer is not None and reply["custodian_key_id"]!=signer:
                return deny("multi-sample-custodian-mismatch")
            checked=single.verify(
                manifest,pinned_manifest_hash,expected_archive_head,
                request,reply,expected_requester,expected_nonce,
                trusted_current_epoch,used,custodian_roots,
                allowed_custodians,revoked_custodians)
        except (TypeError,ValueError,OverflowError) as exc:
            return deny(str(exc))
        if not checked["content_sample_valid"]:
            return deny("multi-sample-verification-failed:"+checked["reason"])
        signer=reply["custodian_key_id"]
        used.add(expected_nonce)
    return {**_out(),"multi_sample_valid":True,"state":"pending-review",
            "reason":"sampled-chunks-verified-no-proof-of-full-archive-custody",
            "sample_count":len(chosen),"total_chunks":len(manifest["chunk_sha256"]),
            "coverage_ppm":coverage,"sampled_indices":chosen,
            "manifest_sha256":manifest_sha}
