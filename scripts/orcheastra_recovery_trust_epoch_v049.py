#!/usr/bin/env python3
"""ORCHEASTRA v0.49: epoch-bound, rotated and revoked recovery witnesses.

This isolated CI fixture demonstrates 2-of-3 governance at trust epoch 2:
A rotates its key, B retains its prior public identity in the roster but
receives a fresh epoch-specific signing key, C is revoked and cannot vote.
The v0.48 keys were deliberately destroyed. v0.49 therefore treats
the newly generated B signing key as a new test generation, NOT as a
cryptographically proven continuity of the previous private key.
The receiver trust manifest is an external input, not externally stored.
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
from orcheastra_recovery_backup_v046 import BACKUP, HEAD, verify_backup
from orcheastra_recovery_quorum_v048 import TRUST as PRIOR_TRUST, VOTES as PRIOR_VOTES
from orcheastra_signed_recovery_anchor_v047 import STATEMENT

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v049"
TRUST = ROOT / "receiver-trust-epoch2.json"
VOTES = ROOT / "epoch2-recovery-votes.json"
DOMAIN = "PALACO:ORCHEASTRA:RECOVERY_TRUST_EPOCH:v1"
RESPONSE_DOMAIN = "PALACO:ORCHEASTRA:RECOVERY_EPOCH_VOTE:v1"
IDS = ("recovery-a", "recovery-b", "recovery-c")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    completed = subprocess.run(["openssl", *args], text=True, capture_output=True,
                               timeout=20, check=False)
    if completed.returncode:
        raise AssertionError("recovery signer operation failed")


def sign(private: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
        input_path, output_path = Path(tmp) / "payload", Path(tmp) / "signature"
        input_path.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(input_path), "-out", str(output_path))
        return output_path.read_bytes()


def vote_payload(identity: str, anchor: dict, epoch: int) -> dict:
    return {"format": RESPONSE_DOMAIN, "identity": identity, "epoch": epoch,
            "anchor": anchor, "authorization": "NONE", "execution": "HOLD"}


def verify(backup: Path, head_raw: bytes, votes: dict, trusted: dict) -> dict:
    if (not isinstance(trusted, dict)
        or set(trusted) != {"format", "epoch", "minimum_epoch",
                            "threshold", "minimum_sequence", "scope",
                            "identities", "previous_trust_sha256"}
        or trusted["format"] != DOMAIN
        or type(trusted["epoch"]) is not int
        or type(trusted["minimum_epoch"]) is not int
        or trusted["epoch"] != 2
        or trusted["minimum_epoch"] != 2
        or trusted["threshold"] != 2
        or type(trusted["minimum_sequence"]) is not int
        or trusted["minimum_sequence"] < 2
        or not isinstance(trusted["identities"], dict)
        or set(trusted["identities"]) != set(IDS)):
        raise AssertionError("independently pinned current trust epoch required")
    previous = parse(PRIOR_TRUST.read_bytes())
    if trusted["previous_trust_sha256"] != sha(canonical(previous)):
        raise AssertionError("trust epoch lacks prior roster reference")
    identity_roster = trusted["identities"]
    if (identity_roster["recovery-c"].get("status") != "REVOKED"
        or identity_roster["recovery-a"].get("status") != "ACTIVE"
        or identity_roster["recovery-b"].get("status") != "ACTIVE"):
        raise AssertionError("unknown revocation status")
    pins = []
    for identity in IDS:
        entry = identity_roster[identity]
        if set(entry) != {"status", "public_key_sha256"}:
            raise AssertionError("invalid key registry schema")
        pin = entry["public_key_sha256"]
        if not isinstance(pin, str) or len(pin) != 64:
            raise AssertionError("invalid key pin")
        pins.append(pin)
    if len(set(pins)) != 3:
        raise AssertionError("reused recovery witness key")
    if (not isinstance(votes, dict)
        or set(votes) != {"format", "votes"}
        or votes["format"] != DOMAIN
        or not isinstance(votes["votes"], list)
        or len(votes["votes"]) != 2):
        raise AssertionError("epoch quorum requires two active witnesses")
    observed, anchor_hashes, anchors = set(), set(), []
    for candidate in votes["votes"]:
        if not isinstance(candidate, dict) or set(candidate) != {
            "id", "payload", "public_hex", "signature_hex"
        }:
            raise AssertionError("malformed epoch witness vote")
        identity = candidate["id"]
        if identity not in IDS or identity in observed:
            raise AssertionError("unknown or repeated witness")
        observed.add(identity)
        if identity_roster[identity]["status"] != "ACTIVE":
            raise AssertionError("revoked witness cannot contribute")
        payload = candidate["payload"]
        if (not isinstance(payload, dict)
            or payload.get("format") != RESPONSE_DOMAIN
            or payload.get("identity") != identity
            or type(payload.get("epoch")) is not int
            or payload["epoch"] != trusted["epoch"]
            or payload.get("authorization") != "NONE"
            or payload.get("execution") != "HOLD"
            or not isinstance(payload.get("anchor"), dict)
            or payload != vote_payload(identity, payload["anchor"], trusted["epoch"])):
            raise AssertionError("wrong epoch or authority in signed vote")
        try:
            public = bytes.fromhex(candidate["public_hex"])
            signature = bytes.fromhex(candidate["signature_hex"])
        except (KeyError, ValueError, TypeError) as error:
            raise AssertionError("bad recovery signature material") from error
        if sha(public) != identity_roster[identity]["public_key_sha256"]:
            raise AssertionError("old or substituted recovery signer")
        if not signature_valid(canonical(payload), signature, public):
            raise AssertionError("invalid epoch-bound signature")
        anchor_hashes.add(sha(canonical(payload["anchor"])))
        anchors.append(payload["anchor"])
    if len(observed) != trusted["threshold"] or len(anchor_hashes) != 1:
        raise AssertionError("insufficient or equivocating active recovery witnesses")
    anchor = anchors[0]
    if (type(anchor.get("sequence")) is not int
        or anchor["sequence"] < trusted["minimum_sequence"]
        or anchor.get("scope") != trusted["scope"]
        or anchor.get("state") != "VERIFIED_HOLD"
        or anchor.get("authorization") != "NONE"
        or anchor.get("execution") != "HOLD"
        or sha(head_raw) != anchor.get("head_sha256")
        or not backup.is_file()
        or sha(backup.read_bytes()) != anchor.get("backup_sha256")):
        raise AssertionError("recovery head rollback or inconsistent scope")
    check = verify_backup(backup, head_raw, anchor["head_sha256"])
    if check["recovery"] != "STAGED_ONLY":
        raise AssertionError("restoration activation prohibited")
    return {**check, "trust_epoch": trusted["epoch"],
            "active_witnesses": sorted(observed), "signature": "QUORUM_VERIFIED"}


def rejected(backup, head, votes, trust, name):
    try:
        verify(backup, head, votes, trust)
    except (AssertionError, KeyError, TypeError, ValueError, OSError):
        return
    raise AssertionError("accepted unsafe trust transition: " + name)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite recovery trust epoch")
    old_trust = parse(PRIOR_TRUST.read_bytes())
    old_record = parse(PRIOR_VOTES.read_bytes())
    anchor = parse(STATEMENT.read_bytes())
    head = HEAD.read_bytes()
    if verify_backup(BACKUP, head, sha(head))["status"] != "VERIFIED_HOLD":
        raise AssertionError("untrusted base recovery archive")
    ROOT.mkdir(mode=0o700, parents=True)
    roster, signed, privates = {}, [], {}
    for identity in IDS[:2]:
        private = ROOT / (identity + "-epoch2-private.pem")
        public = ROOT / (identity + "-epoch2-public.pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        privates[identity] = private
        public_bytes = public.read_bytes()
        roster[identity] = {"status": "ACTIVE",
                            "public_key_sha256": sha(public_bytes)}
        vote = vote_payload(identity, anchor, 2)
        signed.append({"id": identity, "payload": vote,
                       "public_hex": public_bytes.hex(),
                       "signature_hex": sign(private, canonical(vote)).hex()})
    roster[IDS[2]] = {
        "status": "REVOKED",
        "public_key_sha256": old_trust["keys"][IDS[2]],
    }
    trust = {"format": DOMAIN, "epoch": 2, "minimum_epoch": 2,
             "threshold": 2, "minimum_sequence": 2,
             "scope": anchor["scope"], "identities": roster,
             "previous_trust_sha256": sha(canonical(old_trust))}
    record = {"format": DOMAIN, "votes": signed}
    if verify(BACKUP, head, record, trust)["trust_epoch"] != 2:
        raise AssertionError("current two active signers failed")
    rejected(BACKUP, head, record, {**trust, "minimum_epoch": 1},
             "receiver trust epoch downgraded")
    rejected(BACKUP, head, record, {**trust, "previous_trust_sha256": "00"*32},
             "replaced historical trust roster")
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [signed[0], signed[0]]},
             trust, "duplicated votes")
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [signed[0]]},
             trust, "single active signer")
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [
        signed[0], {**signed[1], "signature_hex": "00" * 64}]},
        trust, "forged second signature")
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [
        signed[0], {**signed[1], "public_hex": old_record["votes"][1]["public_hex"]}]},
        trust, "previous key from earlier epoch")
    old_vote = old_record["votes"][2]
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [
        signed[0], {"id": IDS[2],
                    "payload": vote_payload(IDS[2], anchor, 2),
                    "public_hex": old_vote["public_hex"],
                    "signature_hex": old_vote["signature_hex"]}]},
        trust, "revoked witness reused")
    rejected(BACKUP, head, record,
             {**trust, "identities": {**roster, IDS[1]: {
                **roster[IDS[1]], "status": "REVOKED"}}},
             "loss of required quorum after revocation")
    rejected(BACKUP, head, record,
             {**trust, "minimum_sequence": 3}, "older signed anchor")
    dissent = {**anchor, "sequence": 3}
    altered_vote = vote_payload(IDS[1], dissent, 2)
    contradiction = {**signed[1], "payload": altered_vote,
                     "signature_hex": sign(privates[IDS[1]], canonical(altered_vote)).hex()}
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [signed[0], contradiction]},
             trust, "authentic conflicting head")
    unauthorized = vote_payload(IDS[1], {**anchor, "execution": "ALLOW"}, 2)
    rejected(BACKUP, head, {"format": DOMAIN, "votes": [
        signed[0], {**signed[1], "payload": unauthorized,
                    "signature_hex": sign(privates[IDS[1]], canonical(unauthorized)).hex()}]},
        trust, "signed authority escalation")
    for private in privates.values():
        private.unlink()
    TRUST.write_bytes(canonical(trust))
    VOTES.write_bytes(canonical(record))
    print("ORCHEASTRA v0.49: epoch-2 rotation, witness revocation, "
          "10 adversarial trust transitions PASS")


def verify_after_restart() -> None:
    if any(ROOT.glob("*-epoch2-private.pem")):
        raise AssertionError("private witness keys retained")
    result = verify(BACKUP, HEAD.read_bytes(), parse(VOTES.read_bytes()),
                    parse(TRUST.read_bytes()))
    if result["trust_epoch"] != 2 or result["execution"] != "HOLD":
        raise AssertionError("trust transition failed after restart")
    print("ORCHEASTRA v0.49: active epoch quorum retained; recovery HOLD")


def main() -> None:
    if sys.argv[1:] and sys.argv[1] == "--verify-portable":
        if len(sys.argv) != 6:
            raise AssertionError("expected BACKUP HEAD VOTES TRUST")
        result = verify(Path(sys.argv[2]), Path(sys.argv[3]).read_bytes(),
                        parse(Path(sys.argv[4]).read_bytes()),
                        parse(Path(sys.argv[5]).read_bytes()))
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI loopback PostgreSQL required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_after_restart()
    else:
        raise AssertionError("expected --create, --verify, or --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as error:
        print(f"ORCHEASTRA v0.49 FAILED: {error}", file=sys.stderr)
        sys.exit(1)
