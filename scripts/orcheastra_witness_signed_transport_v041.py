#!/usr/bin/env python3
"""ORCHEASTRA v0.41: signed challenge-bound transport responses.

New ephemeral CI transport keys are registered with independent fingerprints.
They sign domain-separated response bytes binding request digest, nonce, endpoint,
identity, statement and original v0.39 endorsement. Their public keys are
DIFFERENT from destroyed v0.39 witness keys; this is a test trust generation.
No network/TLS, production key authority, persistent nonce store or execution.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_evidence_handoff_v037 import BUNDLE_COPY, PIN_COPY, HANDOFF, parse
from orcheastra_witness_quorum_v039 import IDS, TRUST
from orcheastra_witness_transport_v040 import (
    REGISTRY, REQUEST, RESPONSES, validate_responses,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v041"
TRUSTED = ROOT / "transport-key-pins.json"
ENVELOPES = ROOT / "signed-responses.json"
DOMAIN = "PALACO:ORCHEASTRA:SIGNED_TRANSPORT_RESPONSE:v1"
TRUST_DOMAIN = "PALACO:ORCHEASTRA:TRANSPORT_KEY_REGISTRY:v1"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], capture_output=True,
                            text=True, timeout=20, check=False)
    if result.returncode:
        raise AssertionError("OpenSSL Ed25519 signer failed")


def sign(key: Path, payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        source, dest = Path(folder) / "payload", Path(folder) / "signature"
        source.write_bytes(payload)
        openssl("pkeyutl", "-sign", "-inkey", str(key), "-rawin",
                "-in", str(source), "-out", str(dest))
        return dest.read_bytes()


def signed_payload(reply: dict, request: dict, registry: dict) -> dict:
    identity = reply["id"]
    return {
        "format": DOMAIN,
        "identity": identity,
        "endpoint": registry["witnesses"][identity]["endpoint"],
        "challenge": request["challenge"],
        "request_sha256": sha(canonical(request)),
        "request_scope": request["scope"],
        "statement_sha256": sha(canonical(reply["statement"])),
        "endorsement_sha256": sha(canonical(reply["endorsement"])),
        "authorization": "NONE",
        "execution": "HOLD",
    }


def verify_signed(registry: dict, request: dict, responses: list,
                  transport_pins: dict, quorum_pins: dict, bundle: bytes,
                  signer_pin: str, handoff: bytes) -> dict:
    if (not isinstance(transport_pins, dict)
        or transport_pins.get("format") != TRUST_DOMAIN
        or transport_pins.get("generation") != 1
        or transport_pins.get("request_nonce") != request.get("challenge")
        or transport_pins.get("registry_sha256") != sha(canonical(registry))
        or type(transport_pins.get("minimum_generation")) is not int
        or transport_pins["minimum_generation"] != 1
        or not isinstance(transport_pins.get("keys"), dict)
        or set(transport_pins["keys"]) != set(IDS)):
        raise AssertionError("missing independent transport signing trust")
    if not isinstance(responses, list) or len(responses) != len(IDS):
        raise AssertionError("incomplete signed witness response set")

    seen = set()
    underlying = []
    for response in responses:
        if not isinstance(response, dict) or set(response) != {
            "id", "reply", "signed", "public_hex", "signature_hex"
        }:
            raise AssertionError("invalid signed response envelope")
        identity = response["id"]
        if identity not in IDS or identity in seen:
            raise AssertionError("duplicate or unknown signed witness")
        seen.add(identity)
        reply = response["reply"]
        if (not isinstance(reply, dict) or reply.get("id") != identity
            or reply.get("status") != "SIGNED"):
            raise AssertionError("unsigned timeout/status substitution")
        signed = response["signed"]
        if (not isinstance(signed, dict) or signed.get("format") != DOMAIN
            or signed.get("identity") != identity
            or signed.get("endpoint") != reply.get("endpoint")
            or signed.get("challenge") != reply.get("challenge")
            or signed.get("request_sha256") != sha(canonical(request))
            or signed.get("request_scope") != request.get("scope")
            or signed.get("statement_sha256") != sha(canonical(reply["statement"]))
            or signed.get("endorsement_sha256") != sha(canonical(reply["endorsement"]))
            or signed.get("authorization") != "NONE"
            or signed.get("execution") != "HOLD"
            or signed != signed_payload(reply, request, registry)):
            raise AssertionError("transport signature context binding mismatch")
        try:
            public = bytes.fromhex(response["public_hex"])
            signature = bytes.fromhex(response["signature_hex"])
        except (TypeError, ValueError) as err:
            raise AssertionError("non-hex signed witness material") from err
        if sha(public) != transport_pins["keys"][identity]:
            raise AssertionError("transport signing key outside pinned registry")
        if not signature_valid(canonical(signed), signature, public):
            raise AssertionError("invalid transport context signature")
        underlying.append(reply)

    result = validate_responses(
        registry, request, underlying, quorum_pins, bundle, signer_pin, handoff
    )
    if result["execution"] != "HOLD" or result["authorization"] != "NONE":
        raise AssertionError("transport signatures granted authority")
    return {**result, "transport_signatures": len(seen)}


def reject(responses, registry, request, pins, quorum_pins, inputs, scenario):
    try:
        verify_signed(registry, request, responses, pins, quorum_pins, *inputs)
    except (AssertionError, TypeError, KeyError, ValueError, AttributeError):
        return
    raise AssertionError("accepted adversarial signed transport: " + scenario)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite transport trust fixture")
    registry = parse(REGISTRY.read_bytes())
    request = parse(REQUEST.read_bytes())
    replies = json.loads(RESPONSES.read_bytes())
    quorum_pins = parse(TRUST.read_bytes())
    inputs = (BUNDLE_COPY.read_bytes(),
              PIN_COPY.read_text(encoding="ascii").strip(),
              HANDOFF.read_bytes())
    ROOT.mkdir(parents=True, mode=0o700)
    keys, envelopes = {}, []
    for reply in replies:
        identity = reply["id"]
        private = ROOT / f"{identity}-transport-private.pem"
        public = ROOT / f"{identity}-transport-public.pem"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        public_bytes = public.read_bytes()
        keys[identity] = sha(public_bytes)
        payload = signed_payload(reply, request, registry)
        envelopes.append({
            "id": identity, "reply": reply, "signed": payload,
            "public_hex": public_bytes.hex(),
            "signature_hex": sign(private, canonical(payload)).hex(),
        })
    trust = {
        "format": TRUST_DOMAIN, "generation": 1, "minimum_generation": 1,
        "registry_sha256": sha(canonical(registry)),
        "request_nonce": request["challenge"], "keys": keys,
    }
    if len(set(keys.values())) != 3:
        raise AssertionError("transport identities share one key")
    result = verify_signed(registry, request, envelopes, trust,
                           quorum_pins, *inputs)
    if result["transport_signatures"] != 3:
        raise AssertionError("signed transport matrix initially invalid")

    def mutated(index: int, name: str, value):
        changed = list(envelopes)
        changed[index] = {**changed[index], name: value}
        return changed

    original = envelopes[0]
    reject(mutated(0, "signed", {
        **original["signed"], "challenge": "replayed-old-nonce"
    }), registry, request, trust, quorum_pins, inputs, "replayed signed nonce")
    reject(mutated(0, "reply", {
        **original["reply"], "challenge": "replayed-old-nonce"
    }), registry, request, trust, quorum_pins, inputs, "replayed unsigned envelope")
    reject(mutated(0, "reply", {
        **original["reply"], "endpoint": envelopes[1]["reply"]["endpoint"]
    }), registry, request, trust, quorum_pins, inputs, "endpoint substitution")
    reject(mutated(0, "reply", {
        **original["reply"], "statement": {
            **original["reply"]["statement"], "version": 999,
        }
    }), registry, request, trust, quorum_pins, inputs, "statement substitution")
    reject(mutated(0, "signature_hex", "00" * 64),
           registry, request, trust, quorum_pins, inputs, "forged Ed25519 signature")
    reject([envelopes[0], envelopes[0], envelopes[2]],
           registry, request, trust, quorum_pins, inputs, "duplicate transport identity")
    reject(envelopes[:2], registry, request, trust, quorum_pins,
           inputs, "incomplete response set")
    reject(envelopes, registry, {**request, "scope": "wrong-scope"},
           trust, quorum_pins, inputs, "changed request scope")
    reject(envelopes, registry, {**request, "challenge": "new-challenge"},
           trust, quorum_pins, inputs, "new challenge replay")
    reject(envelopes, registry, request,
           {**trust, "keys": {**keys, IDS[0]: "00" * 32}},
           quorum_pins, inputs, "substituted registry key")
    reject(envelopes, registry, request,
           {**trust, "minimum_generation": 2}, quorum_pins, inputs,
           "trust generation rollback")
    reject(mutated(0, "signed", {
        **original["signed"], "execution": "ALLOW"
    }), registry, request, trust, quorum_pins, inputs, "execution escalation")

    for identity in IDS:
        (ROOT / f"{identity}-transport-private.pem").unlink()
    TRUSTED.write_bytes(canonical(trust))
    ENVELOPES.write_bytes(canonical(envelopes))
    print("ORCHEASTRA v0.41: 3 signed challenge-bound responses; 12 attacks rejected")


def verify() -> None:
    if any((ROOT / f"{identity}-transport-private.pem").exists()
           for identity in IDS):
        raise AssertionError("transport signer private key remains")
    result = verify_signed(
        parse(REGISTRY.read_bytes()), parse(REQUEST.read_bytes()),
        json.loads(ENVELOPES.read_bytes()), parse(TRUSTED.read_bytes()),
        parse(TRUST.read_bytes()), BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text(encoding="ascii").strip(), HANDOFF.read_bytes(),
    )
    if result["transport_signatures"] != 3 or result["execution"] != "HOLD":
        raise AssertionError("signed response contract failed restart verification")
    print("ORCHEASTRA v0.41: cryptographically bound transport verified after restart")


def main() -> None:
    if len(sys.argv) == 10 and sys.argv[1] == "--verify-portable":
        result = verify_signed(
            parse(Path(sys.argv[2]).read_bytes()),
            parse(Path(sys.argv[3]).read_bytes()),
            json.loads(Path(sys.argv[4]).read_bytes()),
            parse(Path(sys.argv[5]).read_bytes()),
            parse(Path(sys.argv[6]).read_bytes()),
            Path(sys.argv[7]).read_bytes(),
            Path(sys.argv[8]).read_text(encoding="ascii").strip(),
            Path(sys.argv[9]).read_bytes(),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires isolated loopback PostgreSQL")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create, --verify or --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, TypeError, KeyError, ValueError, AttributeError,
            OSError, subprocess.TimeoutExpired) as err:
        print(f"ORCHEASTRA v0.41 FAILED: {err}", file=sys.stderr)
        sys.exit(1)
