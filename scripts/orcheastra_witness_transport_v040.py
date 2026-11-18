#!/usr/bin/env python3
"""ORCHEASTRA v0.40: fail-closed witness transport/registration contract.

A deterministic, offline CI fixture represents independently addressable
witnesses with an exact, externally pinned endpoint roster. It binds
challenge IDs to the returned quorum claim and preserves strict failure
semantics. It DOES NOT make network calls or demonstrate physical separation.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import (
    BUNDLE_COPY, PIN_COPY, HANDOFF, parse,
)
from orcheastra_witness_quorum_v039 import (
    IDS, DOMAIN as QUORUM_DOMAIN, RECORD, TRUST, verify_quorum,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v040"
REGISTRY = ROOT / "trusted-endpoint-registry.json"
REQUEST = ROOT / "challenge.json"
RESPONSES = ROOT / "responses.json"
DOMAIN = "PALACO:ORCHEASTRA:WITNESS_TRANSPORT:v1"
REQUEST_DOMAIN = "PALACO:ORCHEASTRA:WITNESS_CHALLENGE:v1"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def transport_registry(pins: dict) -> dict:
    # These are logical identifiers, not live service endpoints.
    return {
        "format": DOMAIN,
        "registry_version": 1,
        "minimum_registry_version": 1,
        "quorum": 2,
        "witnesses": {
            witness: {
                "endpoint": f"witness+fixture://{witness}/attest",
                "public_key_sha256": pins["identities"][witness],
                "timeout_ms": 1500,
                "transport": "OFFLINE_SIMULATION",
            } for witness in IDS
        },
    }


def validate_registry(registry: dict, pins: dict) -> None:
    if (not isinstance(registry, dict)
        or registry.get("format") != DOMAIN
        or type(registry.get("registry_version")) is not int
        or type(registry.get("minimum_registry_version")) is not int
        or registry["registry_version"] < registry["minimum_registry_version"]
        or registry.get("quorum") != 2
        or not isinstance(registry.get("witnesses"), dict)
        or set(registry["witnesses"]) != set(IDS)):
        raise AssertionError("untrusted endpoint registry")
    endpoints = []
    for witness in IDS:
        entry = registry["witnesses"][witness]
        if (not isinstance(entry, dict)
            or entry.get("public_key_sha256") != pins["identities"][witness]
            or entry.get("endpoint") != f"witness+fixture://{witness}/attest"
            or entry.get("transport") != "OFFLINE_SIMULATION"
            or type(entry.get("timeout_ms")) is not int
            or entry["timeout_ms"] < 1 or entry["timeout_ms"] > 5000):
            raise AssertionError("endpoint/key binding or timeout policy invalid")
        endpoints.append(entry["endpoint"])
    if len(set(endpoints)) != len(IDS):
        raise AssertionError("duplicate witness endpoints")


def request_fixture(quorum_record: dict) -> dict:
    claim = quorum_record["statements"][0]
    return {
        "format": REQUEST_DOMAIN,
        "challenge": "orcheastra-ci-nonce-v040-0001",
        "scope": claim["high_water"]["scope"],
        "minimum_version": 1,
        "expected_statement_sha256": digest(canonical(claim)),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def validate_responses(registry: dict, request: dict, replies: list,
                       pins: dict, bundle: bytes, signer_pin: str,
                       handoff: bytes) -> dict:
    validate_registry(registry, pins)
    if (not isinstance(request, dict)
        or request.get("format") != REQUEST_DOMAIN
        or request.get("challenge") != "orcheastra-ci-nonce-v040-0001"
        or request.get("authorization") != "NONE"
        or request.get("execution") != "HOLD"
        or type(request.get("minimum_version")) is not int
        or request["minimum_version"] < pins["minimum_version"]
        or not isinstance(replies, list) or len(replies) != len(IDS)):
        raise AssertionError("invalid or incomplete request/response contract")

    observed = set()
    votes = []
    claims = {}
    failures = 0
    for reply in replies:
        if not isinstance(reply, dict):
            raise AssertionError("malformed witness reply")
        identity = reply.get("id")
        if identity not in IDS or identity in observed:
            raise AssertionError("duplicated or unregistered identity")
        observed.add(identity)
        if (reply.get("challenge") != request["challenge"]
            or reply.get("endpoint") != registry["witnesses"][identity]["endpoint"]):
            raise AssertionError("stale challenge or incorrect destination")
        status = reply.get("status")
        if status == "TIMEOUT":
            if set(reply) != {"id", "challenge", "endpoint", "status"}:
                raise AssertionError("timeout supplied unauthenticated evidence")
            failures += 1
            continue
        if status != "SIGNED":
            raise AssertionError("unknown witness response status")
        vote = reply.get("endorsement")
        claim = reply.get("statement")
        if (not isinstance(vote, dict)
            or vote.get("id") != identity
            or not isinstance(claim, dict)
            or claim.get("format") != QUORUM_DOMAIN
            or claim.get("version", 0) < request["minimum_version"]
            or claim.get("high_water", {}).get("scope") != request["scope"]):
            raise AssertionError("invalid witness response scope or key")
        fingerprint = digest(canonical(claim))
        claims[fingerprint] = claim
        votes.append(vote)

    # A contradictory response cannot be masked by two matching votes.
    if len(claims) != 1:
        raise AssertionError("missing/contradictory signed witness statements")
    claim_hash, claim = next(iter(claims.items()))
    if claim_hash != request["expected_statement_sha256"]:
        raise AssertionError("witness claim differs from pinned request")
    if len(votes) < registry["quorum"]:
        raise AssertionError("quorum unavailable")
    result = verify_quorum(
        {"format": QUORUM_DOMAIN, "statements": [claim],
         "endorsements": votes},
        pins, bundle, signer_pin, handoff,
    )
    if result["execution"] != "HOLD" or result["authorization"] != "NONE":
        raise AssertionError("transport response attempts execution")
    return {**result, "transport": "OFFLINE_SIMULATION",
            "timeouts": failures, "registry_version": registry["registry_version"]}


def reject(reg, req, replies, pins, bundle, signer_pin, handoff, reason):
    try:
        validate_responses(reg, req, replies, pins, bundle, signer_pin, handoff)
    except (AssertionError, TypeError, ValueError, KeyError, AttributeError):
        return
    raise AssertionError("unsafe witness transport accepted: " + reason)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite existing transport fixture")
    pinned = parse(TRUST.read_bytes())
    record = parse(RECORD.read_bytes())
    registry = transport_registry(pinned)
    request = request_fixture(record)
    replies = []
    for witness, vote in zip(IDS, record["endorsements"]):
        replies.append({
            "id": witness, "status": "SIGNED",
            "challenge": request["challenge"],
            "endpoint": registry["witnesses"][witness]["endpoint"],
            "statement": record["statements"][0],
            "endorsement": vote,
        })
    bundle = BUNDLE_COPY.read_bytes()
    signer_pin = PIN_COPY.read_text(encoding="ascii").strip()
    handoff = HANDOFF.read_bytes()
    arguments = (pinned, bundle, signer_pin, handoff)
    check = validate_responses(registry, request, replies, *arguments)
    if check["witness_quorum"] != 3 or check["freshness"] != "CURRENT":
        raise AssertionError("three valid witness responses rejected")

    timeouts = list(replies)
    timeouts[2] = {
        "id": IDS[2], "status": "TIMEOUT",
        "challenge": request["challenge"],
        "endpoint": registry["witnesses"][IDS[2]]["endpoint"],
    }
    if validate_responses(registry, request, timeouts, *arguments)["witness_quorum"] != 2:
        raise AssertionError("quorum lost on a single transport timeout")
    two_lost = list(timeouts)
    two_lost[1] = {
        "id": IDS[1], "status": "TIMEOUT",
        "challenge": request["challenge"],
        "endpoint": registry["witnesses"][IDS[1]]["endpoint"],
    }
    reject(registry, request, two_lost, *arguments, "two witnesses unavailable")
    reject(registry, request, [replies[0], replies[0], replies[2]],
           *arguments, "duplicated identity")
    reject(registry, request,
           [{**replies[0], "challenge": "replayed"}, *replies[1:]],
           *arguments, "replayed challenge")
    reject(registry, request,
           [{**replies[0], "endpoint": replies[1]["endpoint"]}, *replies[1:]],
           *arguments, "cross-endpoint substitution")
    bad_claim = {**replies[2]["statement"], "high_water": {
        **replies[2]["statement"]["high_water"], "minimum_sequence": 2}}
    reject(registry, request,
           [*replies[:2], {**replies[2], "statement": bad_claim}],
           *arguments, "contradictory witness response")
    reject({**registry, "witnesses": {
        **registry["witnesses"],
        IDS[0]: {**registry["witnesses"][IDS[0]],
                 "public_key_sha256": "00" * 32}}},
        request, replies, *arguments, "unauthorized endpoint pin")
    reject({**registry, "minimum_registry_version": 2},
           request, replies, *arguments, "registry downgrade")
    reject(registry, {**request, "expected_statement_sha256": "00" * 32},
           replies, *arguments, "incorrect pinned expected statement")
    reject(registry, request,
           [{**replies[0], "status": "ERROR"}, *replies[1:]],
           *arguments, "unknown error transport status")

    ROOT.mkdir(parents=True, mode=0o700)
    REGISTRY.write_bytes(canonical(registry))
    REQUEST.write_bytes(canonical(request))
    RESPONSES.write_bytes(canonical(replies))
    print("ORCHEASTRA v0.40: witness transport registration and 9 negative checks PASS")


def verify() -> None:
    result = validate_responses(
        parse(REGISTRY.read_bytes()), parse(REQUEST.read_bytes()),
        parse(RESPONSES.read_bytes()) if False else json.loads(RESPONSES.read_bytes()),
        parse(TRUST.read_bytes()), BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text(encoding="ascii").strip(), HANDOFF.read_bytes(),
    )
    if result["witness_quorum"] != 3 or result["execution"] != "HOLD":
        raise AssertionError("registered witnesses changed after DB restart")
    print("ORCHEASTRA v0.40: 3 registered witness responses verified after restart")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires CI-only loopback PostgreSQL")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, TypeError, ValueError, KeyError, OSError,
            AttributeError) as error:
        print(f"ORCHEASTRA v0.40 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
