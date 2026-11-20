#!/usr/bin/env python3
"""ORCHEASTRA v0.48: 2-of-3 portable signed recovery quorum, CI ONLY.

Three distinct ephemeral Ed25519 keys endorse the SAME canonical v0.47
recovery anchor. Every supplied vote must be authentic and identical;
even a correctly signed dissent fails closed. No real remote witnesses.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_recovery_backup_v046 import BACKUP, HEAD, verify_backup
from orcheastra_signed_recovery_anchor_v047 import STATEMENT, DOMAIN as ANCHOR_DOMAIN

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v048"
VOTES = ROOT / "recovery-quorum.json"
TRUST = ROOT / "receiver-quorum-trust.json"
DOMAIN = "PALACO:ORCHEASTRA:RECOVERY_QUORUM:v1"
IDS = ("recovery-a", "recovery-b", "recovery-c")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], capture_output=True,
                            text=True, check=False, timeout=20)
    if result.returncode:
        raise AssertionError("fixture signing failed")


def sign(private: Path, data: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        source, target = Path(tmp) / "data", Path(tmp) / "sig"
        source.write_bytes(data)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(source), "-out", str(target))
        return target.read_bytes()


def verify_quorum(backup: Path, head_raw: bytes,
                  envelope: dict, trusted: dict) -> dict:
    if (not isinstance(trusted, dict)
        or set(trusted) != {"format", "threshold", "minimum_sequence",
                           "scope", "keys"}
        or trusted["format"] != DOMAIN
        or type(trusted["threshold"]) is not int
        or trusted["threshold"] != 2
        or type(trusted["minimum_sequence"]) is not int
        or trusted["minimum_sequence"] < 1
        or not isinstance(trusted["keys"], dict)
        or set(trusted["keys"]) != set(IDS)
        or not isinstance(trusted["scope"], str)):
        raise AssertionError("independent quorum trust unavailable")
    fingerprints = list(trusted["keys"].values())
    if (len(set(fingerprints)) != 3
        or any(not isinstance(v, str) or len(v) != 64 for v in fingerprints)):
        raise AssertionError("witness key reuse or invalid independent pins")
    if (not isinstance(envelope, dict)
        or set(envelope) != {"format", "votes"}
        or envelope["format"] != DOMAIN
        or not isinstance(envelope["votes"], list)
        or not 2 <= len(envelope["votes"]) <= 3):
        raise AssertionError("recovery quorum vote count invalid")
    seen = set()
    anchors = set()
    statements = []
    for vote in envelope["votes"]:
        if (not isinstance(vote, dict)
            or set(vote) != {"id", "statement", "public_hex", "signature_hex"}):
            raise AssertionError("malformed recovery endorsement")
        identity = vote["id"]
        if identity not in IDS or identity in seen:
            raise AssertionError("unknown or repeated witness identity")
        seen.add(identity)
        statement = vote["statement"]
        if not isinstance(statement, dict):
            raise AssertionError("malformed signed statement")
        raw = canonical(statement)
        try:
            public = bytes.fromhex(vote["public_hex"])
            signature = bytes.fromhex(vote["signature_hex"])
        except (ValueError, TypeError) as exc:
            raise AssertionError("invalid signing material") from exc
        if sha(public) != trusted["keys"][identity]:
            raise AssertionError("untrusted recovery witness key")
        if not signature_valid(raw, signature, public):
            raise AssertionError("invalid recovery witness signature")
        anchors.add(sha(raw))
        statements.append(statement)
    if len(seen) < trusted["threshold"] or len(anchors) != 1:
        raise AssertionError("missing quorum or authentic conflicting recovery anchor")
    anchor = statements[0]
    if (set(anchor) != {"format", "sequence", "head_sha256",
                        "backup_sha256", "scope", "state",
                        "authorization", "execution"}
        or anchor["format"] != ANCHOR_DOMAIN
        or type(anchor["sequence"]) is not int
        or anchor["sequence"] < trusted["minimum_sequence"]
        or anchor["scope"] != trusted["scope"]
        or anchor["state"] != "VERIFIED_HOLD"
        or anchor["authorization"] != "NONE"
        or anchor["execution"] != "HOLD"):
        raise AssertionError("quorum rollback, scope or authority escalation")
    if (sha(head_raw) != anchor["head_sha256"]
        or not backup.is_file()
        or sha(backup.read_bytes()) != anchor["backup_sha256"]):
        raise AssertionError("quorum backup or head changed")
    verified = verify_backup(backup, head_raw, anchor["head_sha256"])
    if verified["status"] != "VERIFIED_HOLD":
        raise AssertionError("recovered nonce not consumed")
    return {**verified, "signature": "QUORUM_VERIFIED",
            "quorum": len(seen), "sequence": anchor["sequence"],
            "offline": True}


def must_reject(backup: Path, head: bytes, votes: dict,
                trust: dict, label: str) -> None:
    try:
        verify_quorum(backup, head, votes, trust)
    except (AssertionError, KeyError, ValueError, TypeError, OSError):
        return
    raise AssertionError("unsafe recovery admitted: " + label)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refuse overwrite of recovery witnesses")
    head_raw = HEAD.read_bytes()
    if verify_backup(BACKUP, head_raw, sha(head_raw))["status"] != "VERIFIED_HOLD":
        raise AssertionError("unverified predecessor backup")
    anchor = parse(STATEMENT.read_bytes())
    if anchor.get("sequence") != 2:
        raise AssertionError("requires v0.47 signed head sequence 2")
    ROOT.mkdir(mode=0o700, parents=True)
    votes = []
    pins = {}
    for identity in IDS:
        private = ROOT / (identity + "-private.pem")
        public = ROOT / (identity + "-public.pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        pub = public.read_bytes()
        pins[identity] = sha(pub)
        votes.append({"id": identity, "statement": anchor,
                      "public_hex": pub.hex(),
                      "signature_hex": sign(private, canonical(anchor)).hex()})
    trusted = {"format": DOMAIN, "threshold": 2, "minimum_sequence": 2,
               "scope": anchor["scope"], "keys": pins}
    record = {"format": DOMAIN, "votes": votes}
    if verify_quorum(BACKUP, head_raw, record, trusted)["quorum"] != 3:
        raise AssertionError("three witness quorum unavailable")
    two = {"format": DOMAIN, "votes": votes[:2]}
    if verify_quorum(BACKUP, head_raw, two, trusted)["quorum"] != 2:
        raise AssertionError("two-of-three availability failed")
    must_reject(BACKUP, head_raw, {"format": DOMAIN, "votes": votes[:1]},
                trusted, "only one witness")
    must_reject(BACKUP, head_raw, {"format": DOMAIN,
                "votes": [votes[0], votes[0]]}, trusted, "duplicate witness")
    must_reject(BACKUP, head_raw, {"format": DOMAIN,
                "votes": [votes[0], {**votes[1], "signature_hex": "00" * 64}]},
                trusted, "forged signature")
    must_reject(BACKUP, head_raw, two,
                {**trusted, "minimum_sequence": 3}, "minimum floor advanced")
    must_reject(BACKUP, head_raw, two,
                {**trusted, "keys": {**pins, IDS[1]: pins[IDS[0]]}},
                "duplicate independent key pin")
    must_reject(BACKUP, head_raw, two,
                {**trusted, "scope": "untrusted-scope"}, "scope substitution")
    must_reject(BACKUP, head_raw, two,
                {**trusted, "keys": {**pins, IDS[0]: "00" * 32}},
                "untrusted signing key")
    old = {**anchor, "sequence": 1}
    # An AUTHENTIC, correctly signed old statement must fail the version floor.
    private0 = ROOT / (IDS[0] + "-private.pem")
    private1 = ROOT / (IDS[1] + "-private.pem")
    old_votes = [
        {**votes[0], "statement": old,
         "signature_hex": sign(private0, canonical(old)).hex()},
        {**votes[1], "statement": old,
         "signature_hex": sign(private1, canonical(old)).hex()},
    ]
    must_reject(BACKUP, head_raw, {"format": DOMAIN, "votes": old_votes},
                trusted, "valid historical signed quorum")
    # A third valid but contradictory witness response must NOT be ignored.
    dissent = {**anchor, "sequence": 3}
    dissent_vote = {**votes[2], "statement": dissent,
                    "signature_hex": sign(
                        ROOT / (IDS[2] + "-private.pem"),
                        canonical(dissent)).hex()}
    must_reject(BACKUP, head_raw, {"format": DOMAIN,
                "votes": [*votes[:2], dissent_vote]}, trusted,
                "authentically signed conflicting head")
    unauthorized = {**anchor, "execution": "ALLOW"}
    must_reject(BACKUP, head_raw, {"format": DOMAIN, "votes": [
        {**votes[0], "statement": unauthorized,
         "signature_hex": sign(private0, canonical(unauthorized)).hex()},
        {**votes[1], "statement": unauthorized,
         "signature_hex": sign(private1, canonical(unauthorized)).hex()},
    ]}, trusted, "authentically signed authority escalation")
    tampered = ROOT / "tampered.sqlite3"
    shutil.copyfile(BACKUP, tampered)
    with tampered.open("r+b") as file:
        file.write(b"X")
    must_reject(tampered, head_raw, two, trusted, "damaged backup")
    must_reject(ROOT / "missing.sqlite3", head_raw, two, trusted,
                "missing backup")
    for identity in IDS:
        (ROOT / (identity + "-private.pem")).unlink()
    VOTES.write_bytes(canonical(record))
    TRUST.write_bytes(canonical(trusted))
    print("ORCHEASTRA v0.48: signed recovery quorum (2/3), "
          "authentic dissent/old quorum rejected; PASS")


def verify() -> None:
    if any((ROOT / (identity + "-private.pem")).exists() for identity in IDS):
        raise AssertionError("test witness signing key retained")
    result = verify_quorum(
        BACKUP, HEAD.read_bytes(), parse(VOTES.read_bytes()),
        parse(TRUST.read_bytes()),
    )
    if result["quorum"] != 3 or result["execution"] != "HOLD":
        raise AssertionError("recovery quorum changed after restart")
    print("ORCHEASTRA v0.48: recovery quorum unchanged after restart; HOLD")


def main() -> None:
    if len(sys.argv) == 6 and sys.argv[1] == "--verify-portable":
        result = verify_quorum(
            Path(sys.argv[2]), Path(sys.argv[3]).read_bytes(),
            parse(Path(sys.argv[4]).read_bytes()),
            parse(Path(sys.argv[5]).read_bytes()),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires disposable loopback CI")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create/--verify/--verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.48 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
