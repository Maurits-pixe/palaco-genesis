#!/usr/bin/env python3
"""ORCHEASTRA v0.50: root-signed recovery trust transition (CI fixture).

A separate ephemeral Ed25519 CI root signs an exact epoch-1 -> epoch-2
transition contract. The *receiver-supplied* root pin and minimum epoch are
required inputs. A valid root signature does not override fail-closed policy:
only A/B key rotation, C revocation and an unchanged quorum are accepted.
No operational root, independently provisioned pins, deployment or execution.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_recovery_backup_v046 import BACKUP, HEAD
from orcheastra_recovery_quorum_v048 import TRUST as PREVIOUS_TRUST
from orcheastra_recovery_trust_epoch_v049 import (
    TRUST as CURRENT_TRUST, VOTES, verify as verify_current, IDS,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v050"
CERT = ROOT / "root-transition-certificate.json"
SIG = ROOT / "root-transition-certificate.sig"
PUBLIC = ROOT / "ci-root-public.pem"
PRIVATE = ROOT / "ci-root-private.pem"
PIN = ROOT / "independent-root-trust.json"
DOMAIN = "PALACO:ORCHEASTRA:ROOT_TRUST_TRANSITION:v1"
PIN_DOMAIN = "PALACO:ORCHEASTRA:ROOT_PIN_POLICY:v1"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def openssl(*args: str) -> None:
    done = subprocess.run(["openssl", *args], capture_output=True,
                          text=True, timeout=20, check=False)
    if done.returncode:
        raise AssertionError("CI root Ed25519 operation failed")


def sign(payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        data = Path(folder) / "payload"
        signature = Path(folder) / "signature"
        data.write_bytes(payload)
        openssl("pkeyutl", "-sign", "-inkey", str(PRIVATE),
                "-rawin", "-in", str(data), "-out", str(signature))
        return signature.read_bytes()


def transition(previous: dict, current: dict) -> dict:
    return {
        "format": DOMAIN,
        "source_epoch": 1, "target_epoch": 2,
        "previous_trust_sha256": digest(canonical(previous)),
        "current_trust_sha256": digest(canonical(current)),
        "required_scope": current["scope"],
        "required_quorum": 2,
        "minimum_sequence": current["minimum_sequence"],
        "rotated": ["recovery-a", "recovery-b"],
        "revoked": ["recovery-c"],
        "authorization": "NONE",
        "execution": "HOLD",
    }


def verify_root(backup: Path, head: bytes, votes: dict, current: dict,
                previous: dict, cert_raw: bytes, signature: bytes,
                root_public: bytes, root_policy: dict) -> dict:
    if (not isinstance(root_policy, dict)
        or set(root_policy) != {
            "format", "root_public_sha256", "minimum_epoch",
            "required_scope", "minimum_sequence"}
        or root_policy["format"] != PIN_DOMAIN
        or type(root_policy["minimum_epoch"]) is not int
        or root_policy["minimum_epoch"] != 2
        or type(root_policy["minimum_sequence"]) is not int
        or root_policy["minimum_sequence"] < 2
        or not isinstance(root_policy["root_public_sha256"], str)
        or len(root_policy["root_public_sha256"]) != 64
        or digest(root_public) != root_policy["root_public_sha256"]):
        raise AssertionError("root trust pin or monotonic receiver floor unavailable")
    if not signature_valid(cert_raw, signature, root_public):
        raise AssertionError("root transition not authentically signed")
    certificate = parse(cert_raw)
    if not isinstance(previous, dict) or not isinstance(current, dict):
        raise AssertionError("untrusted transition registries")
    if (not isinstance(certificate, dict)
        or certificate != transition(previous, current)
        or type(certificate.get("source_epoch")) is not int
        or type(certificate.get("target_epoch")) is not int
        or certificate["target_epoch"] < root_policy["minimum_epoch"]
        or certificate["minimum_sequence"] < root_policy["minimum_sequence"]
        or certificate["required_scope"] != root_policy["required_scope"]
        or certificate["authorization"] != "NONE"
        or certificate["execution"] != "HOLD"):
        raise AssertionError("root-signed transition violates pinned policy")
    if (previous.get("format") != "PALACO:ORCHEASTRA:RECOVERY_QUORUM:v1"
        or previous.get("threshold") != 2
        or previous.get("minimum_sequence") != 2
        or not isinstance(previous.get("keys"), dict)
        or set(previous["keys"]) != set(IDS)
        or current.get("epoch") != 2
        or current.get("minimum_epoch") != 2
        or current.get("threshold") != 2
        or current.get("previous_trust_sha256") != digest(canonical(previous))
        or current.get("scope") != previous.get("scope")
        or current.get("minimum_sequence") != previous["minimum_sequence"]
        or not isinstance(current.get("identities"), dict)
        or set(current["identities"]) != set(IDS)):
        raise AssertionError("root transition does not link exact trust generations")
    roster = current["identities"]
    if (not all(roster[name].get("status") == "ACTIVE"
                and roster[name].get("public_key_sha256") != previous["keys"][name]
                for name in IDS[:2])
        or roster[IDS[2]].get("status") != "REVOKED"
        or roster[IDS[2]].get("public_key_sha256") != previous["keys"][IDS[2]]):
        raise AssertionError("rotation/revocation set violates root policy")
    output = verify_current(backup, head, votes, current, previous)
    if (output["execution"] != "HOLD"
        or output["authorization"] != "NONE"
        or output["recovery"] != "STAGED_ONLY"):
        raise AssertionError("root signature cannot grant recovery activation")
    return {**output, "root_transition": "VERIFIED",
            "root_epoch": certificate["target_epoch"], "offline": True}


def must_reject(inputs: tuple, name: str) -> None:
    try:
        verify_root(*inputs)
    except (AssertionError, ValueError, TypeError, KeyError, OSError):
        return
    raise AssertionError("unsafe root transition accepted: " + name)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refuse to overwrite root trust fixture")
    previous = parse(PREVIOUS_TRUST.read_bytes())
    current = parse(CURRENT_TRUST.read_bytes())
    votes = parse(VOTES.read_bytes())
    head = HEAD.read_bytes()
    ROOT.mkdir(mode=0o700, parents=True)
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC))
    certificate = transition(previous, current)
    signed = canonical(certificate)
    signature = sign(signed)
    root_pub = PUBLIC.read_bytes()
    policy = {
        "format": PIN_DOMAIN,
        "root_public_sha256": digest(root_pub),
        "minimum_epoch": 2,
        "minimum_sequence": 2,
        "required_scope": current["scope"],
    }
    args = (BACKUP, head, votes, current, previous, signed,
            signature, root_pub, policy)
    verified = verify_root(*args)
    if verified["root_transition"] != "VERIFIED":
        raise AssertionError("root-signed baseline was rejected")

    must_reject((*args[:5], canonical({**certificate, "target_epoch": 3}),
                 *args[6:]), "unsigned transition mutation")
    must_reject((*args[:6], b"\x00" * 64, *args[7:]),
                "root signature forgery")
    must_reject((*args[:8], {**policy, "root_public_sha256": "00" * 32}),
                "untrusted root key")
    must_reject((*args[:8], {**policy, "minimum_epoch": 3}),
                "advanced root trust floor")
    must_reject((*args[:8], {**policy, "required_scope": "foreign-scope"}),
                "unexpected receiver scope")
    must_reject((*args[:3], previous, previous, *args[5:]),
                "current roster silently rolled back")
    must_reject((*args[:3], {**current, "previous_trust_sha256": "00" * 32},
                 *args[4:]), "previous generation substitution")
    must_reject((*args[:3], {**current, "identities": {
        **current["identities"], IDS[2]: {
            **current["identities"][IDS[2]], "status": "ACTIVE"}}},
        *args[4:]), "revoked witness reactivated")
    must_reject((*args[:3], {**current, "threshold": 1}, *args[4:]),
                "root quorum threshold weakening")

    old = {**certificate, "target_epoch": 1}
    old_raw = canonical(old)
    must_reject((*args[:5], old_raw, sign(old_raw), *args[7:]),
                "genuinely root-signed historical epoch")
    unauthorized = {**certificate, "execution": "ALLOW"}
    unauthorized_raw = canonical(unauthorized)
    must_reject((*args[:5], unauthorized_raw, sign(unauthorized_raw), *args[7:]),
                "genuinely root-signed execution escalation")
    illicit = {**certificate, "revoked": [], "rotated": list(IDS)}
    illicit_raw = canonical(illicit)
    must_reject((*args[:5], illicit_raw, sign(illicit_raw), *args[7:]),
                "root-signed unapproved revocation policy")

    PRIVATE.unlink()
    CERT.write_bytes(signed)
    SIG.write_bytes(signature)
    PIN.write_bytes(canonical(policy))
    print("ORCHEASTRA v0.50: root-signed epoch transition, 12 hostile scenarios PASS")


def verify_restart() -> None:
    if PRIVATE.exists():
        raise AssertionError("root private key not destroyed")
    result = verify_root(
        BACKUP, HEAD.read_bytes(), parse(VOTES.read_bytes()),
        parse(CURRENT_TRUST.read_bytes()),
        parse(PREVIOUS_TRUST.read_bytes()), CERT.read_bytes(),
        SIG.read_bytes(), PUBLIC.read_bytes(), parse(PIN.read_bytes()),
    )
    if result["root_epoch"] != 2:
        raise AssertionError("root transition missing after restart")
    print("ORCHEASTRA v0.50: signed root transition reverified, STAGED_ONLY HOLD")


def main() -> None:
    if sys.argv[1:2] == ["--verify-portable"]:
        if len(sys.argv) != 11:
            raise AssertionError("expected BACKUP HEAD VOTES CURRENT PREVIOUS CERT SIGNATURE ROOT_PUBLIC ROOT_POLICY")
        result = verify_root(
            Path(sys.argv[2]), Path(sys.argv[3]).read_bytes(),
            parse(Path(sys.argv[4]).read_bytes()),
            parse(Path(sys.argv[5]).read_bytes()),
            parse(Path(sys.argv[6]).read_bytes()),
            Path(sys.argv[7]).read_bytes(), Path(sys.argv[8]).read_bytes(),
            Path(sys.argv[9]).read_bytes(),
            parse(Path(sys.argv[10]).read_bytes()),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI only")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create, --verify, --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.50 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
