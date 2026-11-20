#!/usr/bin/env python3
"""ORCHEASTRA v0.52 -- fail-closed root incident review gate (CI-only).

A signed two-of-three *review* quorum binds an incident, evidence digest,
and the v0.51 custody proof. Review acceptance means REVIEW_READY_HOLD,
NEVER a new trust root, authorized recovery, or execution.

The keypairs and trust pins are generated on one disposable runner; there
are no live independent reviewers, trusted timestamps, production identities
or off-runner root custody.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_recovery_bundle_v036 import signature_valid
from orcheastra_root_custody_v051 import (
    CERT as CUSTODY_CERT, OLD_SIGNATURE, NEW_SIGNATURE,
    OLD_PUBLIC, NEW_PUBLIC, POLICY, WITNESS_PUBLIC, WITNESS_CERT,
    verify_handoff,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v052"
CASE = ROOT / "incident-case.json"
VOTES = ROOT / "review-votes.json"
TRUST = ROOT / "reviewer-trust.json"
EVIDENCE = ROOT / "incident-evidence.json"
DOMAIN = "PALACO:ORCHEASTRA:ROOT_INCIDENT_REVIEW:v1"
VOTE_DOMAIN = "PALACO:ORCHEASTRA:ROOT_INCIDENT_REVIEW_VOTE:v1"
TRUST_DOMAIN = "PALACO:ORCHEASTRA:ROOT_REVIEW_TRUST:v1"
REVIEWERS = ("review-a", "review-b", "review-c")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    done = subprocess.run(["openssl", *args], capture_output=True,
                          text=True, timeout=20, check=False)
    if done.returncode:
        raise AssertionError("fixture reviewer signing failed")


def sign(private: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        message, signature = Path(directory) / "payload", Path(directory) / "sig"
        message.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(message), "-out", str(signature))
        return signature.read_bytes()


def vote_payload(identity: str, case_sha: str, decision: str) -> dict:
    return {"format": VOTE_DOMAIN, "reviewer": identity,
            "case_sha256": case_sha, "decision": decision,
            "authorization": "NONE", "execution": "HOLD"}


def verify_review(case: dict, votes: dict, trust: dict, evidence_raw: bytes,
                  custody_files: tuple) -> dict:
    # The previously endorsed root custody proof is checked before
    # considering any reviewer decision. This NEVER validates a replacement root.
    custody = verify_handoff(*custody_files)
    if custody["custody"] != "DUAL_SIGNATURE_VERIFIED":
        raise AssertionError("root custody provenance not trusted")
    if (not isinstance(trust, dict)
        or set(trust) != {"format", "threshold", "reviewer_keys",
                          "required_scope", "minimum_generation"}
        or trust["format"] != TRUST_DOMAIN
        or type(trust["threshold"]) is not int or trust["threshold"] != 2
        or type(trust["minimum_generation"]) is not int
        or trust["minimum_generation"] != 2
        or not isinstance(trust["reviewer_keys"], dict)
        or set(trust["reviewer_keys"]) != set(REVIEWERS)
        or len(set(trust["reviewer_keys"].values())) != 3):
        raise AssertionError("receiver reviewer trust unavailable")
    if (not isinstance(case, dict)
        or set(case) != {"format", "incident_id", "incident_kind",
                        "root_generation", "root_public_sha256",
                        "custody_certificate_sha256", "evidence_sha256",
                        "scope", "requested_action", "authorization", "execution"}
        or case["format"] != DOMAIN
        or not isinstance(case["incident_id"], str)
        or len(case["incident_id"]) != 64
        or any(letter not in "0123456789abcdef" for letter in case["incident_id"])
        or case["incident_kind"] not in ("LOST_ROOT", "SUSPECTED_COMPROMISE")
        or type(case["root_generation"]) is not int
        or case["root_generation"] != trust["minimum_generation"]
        or case["root_public_sha256"] != sha(custody_files[4])
        or case["custody_certificate_sha256"] != sha(custody_files[0])
        or case["scope"] != trust["required_scope"]
        or case["evidence_sha256"] != sha(evidence_raw)
        or case["requested_action"] != "HUMAN_REVIEW_ONLY"
        or case["authorization"] != "NONE"
        or case["execution"] != "HOLD"):
        raise AssertionError("root incident case malformed or evidence mismatch")
    evidence = parse(evidence_raw)
    if (set(evidence) != {"incident_id", "kind", "reported_root_sha256",
                         "report", "authorization", "execution"}
        or evidence["incident_id"] != case["incident_id"]
        or evidence["kind"] != case["incident_kind"]
        or evidence["reported_root_sha256"] != case["root_public_sha256"]
        or evidence["authorization"] != "NONE"
        or evidence["execution"] != "HOLD"
        or not isinstance(evidence["report"], str)
        or not evidence["report"]):
        raise AssertionError("incident evidence does not bind reported root")
    if (not isinstance(votes, dict)
        or set(votes) != {"format", "votes"} or votes["format"] != DOMAIN
        or not isinstance(votes["votes"], list)
        or not 2 <= len(votes["votes"]) <= 3):
        raise AssertionError("insufficient reviewer votes")
    seen, decisions = set(), set()
    case_digest = sha(canonical(case))
    for ballot in votes["votes"]:
        if not isinstance(ballot, dict) or set(ballot) != {
            "id", "payload", "public_hex", "signature_hex"
        }:
            raise AssertionError("malformed reviewer ballot")
        identity = ballot["id"]
        if identity not in REVIEWERS or identity in seen:
            raise AssertionError("untrusted or duplicate reviewer identity")
        seen.add(identity)
        payload = ballot["payload"]
        if not isinstance(payload, dict) or payload != vote_payload(
            identity, case_digest, payload.get("decision")
        ) or payload["decision"] not in ("REVIEW", "REJECT"):
            raise AssertionError("reviewer decision not bound to incident")
        try:
            public = bytes.fromhex(ballot["public_hex"])
            signature = bytes.fromhex(ballot["signature_hex"])
        except (KeyError, ValueError, TypeError) as exc:
            raise AssertionError("malformed reviewer signature") from exc
        if sha(public) != trust["reviewer_keys"][identity]:
            raise AssertionError("untrusted reviewer public key")
        if not signature_valid(canonical(payload), signature, public):
            raise AssertionError("invalid reviewer Ed25519 signature")
        decisions.add(payload["decision"])
    if len(seen) < trust["threshold"] or decisions != {"REVIEW"}:
        raise AssertionError("review quorum rejected or conflicted")
    return {"decision": "REVIEW_READY_HOLD", "reviewers": len(seen),
            "authorization": "NONE", "execution": "HOLD",
            "trust_change": "DENIED", "root_activation": "DENIED"}


def custody_inputs() -> tuple:
    return (CUSTODY_CERT.read_bytes(), OLD_SIGNATURE.read_bytes(),
            NEW_SIGNATURE.read_bytes(), OLD_PUBLIC.read_bytes(),
            NEW_PUBLIC.read_bytes(), parse(POLICY.read_bytes()),
            WITNESS_PUBLIC.read_bytes(), WITNESS_CERT.read_bytes())


def rejected(case, votes, trust, evidence, inputs, scenario: str) -> None:
    try:
        verify_review(case, votes, trust, evidence, inputs)
    except (AssertionError, ValueError, TypeError, KeyError, OSError):
        return
    raise AssertionError("unsafe incident accepted: " + scenario)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refuse to overwrite root incident evidence")
    inputs = custody_inputs()
    verify_handoff(*inputs)
    ROOT.mkdir(mode=0o700, parents=True)
    incident_id = secrets.token_hex(32)
    scope = inputs[5]["scope"]
    evidence = {"incident_id": incident_id, "kind": "SUSPECTED_COMPROMISE",
                "reported_root_sha256": sha(inputs[4]),
                "report": "CI fixture: suspected unauthorized signing; no release.",
                "authorization": "NONE", "execution": "HOLD"}
    raw = canonical(evidence)
    case = {"format": DOMAIN, "incident_id": incident_id,
            "incident_kind": evidence["kind"], "root_generation": 2,
            "root_public_sha256": sha(inputs[4]),
            "custody_certificate_sha256": sha(inputs[0]),
            "evidence_sha256": sha(raw), "scope": scope,
            "requested_action": "HUMAN_REVIEW_ONLY",
            "authorization": "NONE", "execution": "HOLD"}
    pins, ballots, privates = {}, [], {}
    for reviewer in REVIEWERS:
        private, public = ROOT / (reviewer + "-private.pem"), ROOT / (reviewer + ".pem")
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
        privates[reviewer] = private
        pub = public.read_bytes()
        pins[reviewer] = sha(pub)
        payload = vote_payload(reviewer, sha(canonical(case)), "REVIEW")
        ballots.append({"id": reviewer, "payload": payload,
                        "public_hex": pub.hex(),
                        "signature_hex": sign(private, canonical(payload)).hex()})
    trust = {"format": TRUST_DOMAIN, "threshold": 2, "reviewer_keys": pins,
             "required_scope": scope, "minimum_generation": 2}
    record = {"format": DOMAIN, "votes": ballots}
    if verify_review(case, record, trust, raw, inputs)["decision"] != "REVIEW_READY_HOLD":
        raise AssertionError("baseline review quorum invalid")
    two = {"format": DOMAIN, "votes": ballots[:2]}
    if verify_review(case, two, trust, raw, inputs)["reviewers"] != 2:
        raise AssertionError("two reviewer quorum unavailable")
    rejected(case, {"format": DOMAIN, "votes": ballots[:1]}, trust, raw, inputs,
             "single reviewer")
    rejected(case, {"format": DOMAIN, "votes": [ballots[0], ballots[0]]},
             trust, raw, inputs, "duplicate reviewer")
    rejected(case, {"format": DOMAIN, "votes": [
        ballots[0], {**ballots[1], "signature_hex": "00"*64}]},
        trust, raw, inputs, "forged signature")
    rejected({**case, "requested_action": "ACTIVATE_ROOT"}, two, trust, raw, inputs,
             "root activation request")
    rejected({**case, "root_public_sha256": "00"*32}, two, trust, raw, inputs,
             "unknown proposed root")
    rejected({**case, "root_generation": 1}, two, trust, raw, inputs,
             "generation rollback")
    rejected(case, two, trust, b"{}", inputs, "missing incident evidence")
    rejected(case, two, {**trust, "required_scope": "foreign-scope"}, raw, inputs,
             "scope substitution")
    rejected(case, two, {**trust, "reviewer_keys": {**pins,
             REVIEWERS[1]: pins[REVIEWERS[0]]}}, raw, inputs, "reused reviewer key")
    rejection = vote_payload(REVIEWERS[1], sha(canonical(case)), "REJECT")
    dissenter = {**ballots[1], "payload": rejection,
                 "signature_hex": sign(privates[REVIEWERS[1]], canonical(rejection)).hex()}
    rejected(case, {"format": DOMAIN, "votes": [ballots[0], dissenter]},
             trust, raw, inputs, "authentic dissent")
    rejected(case, two, trust, raw, (*inputs[:2], b"forged", *inputs[3:]),
             "unverified custody chain")
    revoked = {**case, "authorization": "GRANTED"}
    rejected(revoked, two, trust, raw, inputs, "unauthorized authority escalation")
    for private in privates.values():
        private.unlink()
    CASE.write_bytes(canonical(case))
    VOTES.write_bytes(canonical(record))
    TRUST.write_bytes(canonical(trust))
    EVIDENCE.write_bytes(raw)
    print("ORCHEASTRA v0.52: 2-of-3 incident review; 12 hostile cases denied, "
          "decision REVIEW_READY_HOLD only")


def verify_restart() -> None:
    if any(ROOT.glob("*-private.pem")):
        raise AssertionError("reviewer private keys retained")
    result = verify_review(parse(CASE.read_bytes()), parse(VOTES.read_bytes()),
                           parse(TRUST.read_bytes()), EVIDENCE.read_bytes(),
                           custody_inputs())
    if result["decision"] != "REVIEW_READY_HOLD" or result["root_activation"] != "DENIED":
        raise AssertionError("root recovery gate state changed after restart")
    print("ORCHEASTRA v0.52: incident review remains HOLD after restart")


def main() -> None:
    if sys.argv[1:2] == ["--verify-portable"]:
        if len(sys.argv) != 14:
            raise AssertionError("expected CASE VOTES TRUST EVIDENCE CUSTODY_CERT OLD_SIG NEW_SIG OLD_PUBLIC NEW_PUBLIC CUSTODY_POLICY HIST_PUBLIC HIST_CERT")
        files = [Path(p) for p in sys.argv[2:]]
        result = verify_review(
            parse(files[0].read_bytes()), parse(files[1].read_bytes()),
            parse(files[2].read_bytes()), files[3].read_bytes(),
            (files[4].read_bytes(), files[5].read_bytes(), files[6].read_bytes(),
             files[7].read_bytes(), files[8].read_bytes(),
             parse(files[9].read_bytes()), files[10].read_bytes(), files[11].read_bytes()))
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI fixture required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create/--verify/--verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.52 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
