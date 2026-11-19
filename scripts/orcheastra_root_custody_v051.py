#!/usr/bin/env python3
"""ORCHEASTRA v0.51: dual-signature root custody rotation CI fixture.

The v0.50 root private key was destroyed. Consequently this module does NOT
pretend to rotate that historical root. It creates a new, two-generation
CI custody lineage whose handoff is signed by BOTH ephemeral roots; it binds
the v0.50 *public* root fingerprint as audited predecessor context only.
A separately supplied receiver pin and monotonic minimum root generation are
required. Root loss, compromised-root allegation or missing counter-signature
always yields HOLD. No HSM, independent operator or deployed authority.
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
from orcheastra_root_transition_v050 import (
    CERT as WITNESS_CERT, SIG as WITNESS_SIG, PUBLIC as WITNESS_PUBLIC,
    PIN as WITNESS_PIN, verify_root,
)
from orcheastra_recovery_backup_v046 import BACKUP, HEAD
from orcheastra_recovery_trust_epoch_v049 import TRUST as CURRENT, VOTES
from orcheastra_recovery_quorum_v048 import TRUST as PREVIOUS

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v051"
CERT = ROOT / "root-custody-handoff.json"
OLD_SIGNATURE = ROOT / "prior-root.sig"
NEW_SIGNATURE = ROOT / "successor-root.sig"
OLD_PUBLIC = ROOT / "prior-root-public.pem"
NEW_PUBLIC = ROOT / "successor-root-public.pem"
POLICY = ROOT / "receiver-root-custody-policy.json"
DOMAIN = "PALACO:ORCHEASTRA:ROOT_CUSTODY_HANDOFF:v1"
POLICY_DOMAIN = "PALACO:ORCHEASTRA:ROOT_CUSTODY_RECEIVER:v1"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], check=False,
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise AssertionError("ephemeral Ed25519 root operation failed")


def sign(private: Path, raw: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        source, result = Path(folder) / "payload", Path(folder) / "signature"
        source.write_bytes(raw)
        openssl("pkeyutl", "-sign", "-inkey", str(private),
                "-rawin", "-in", str(source), "-out", str(result))
        return result.read_bytes()


def handoff(old_public: bytes, new_public: bytes, predecessor: bytes,
            scope: str) -> dict:
    return {"format": DOMAIN,
            "from_generation": 1, "to_generation": 2,
            "from_root_sha256": sha(old_public),
            "to_root_sha256": sha(new_public),
            "historical_v050_root_sha256": sha(predecessor),
            "v050_certificate_sha256": sha(WITNESS_CERT.read_bytes()),
            "scope": scope, "rotation": "DUAL_SIGNATURE",
            "lost_key": False, "compromised": False,
            "authorization": "NONE", "execution": "HOLD"}


def verify_handoff(cert_raw: bytes, old_sig: bytes, new_sig: bytes,
                   old_public: bytes, new_public: bytes, policy: dict,
                   historical_public: bytes, historical_certificate: bytes) -> dict:
    if (not isinstance(policy, dict)
        or set(policy) != {"format", "minimum_root_generation",
                           "expected_old_root_sha256",
                           "expected_new_root_sha256",
                           "historical_v050_root_sha256",
                           "v050_certificate_sha256", "scope"}
        or policy["format"] != POLICY_DOMAIN
        or type(policy["minimum_root_generation"]) is not int
        or policy["minimum_root_generation"] != 2
        or sha(old_public) != policy["expected_old_root_sha256"]
        or sha(new_public) != policy["expected_new_root_sha256"]
        or sha(historical_public) != policy["historical_v050_root_sha256"]
        or sha(historical_certificate) != policy["v050_certificate_sha256"]
        or policy["expected_old_root_sha256"] == policy["expected_new_root_sha256"]):
        raise AssertionError("root custody pins / minimum generation unavailable")
    if not signature_valid(cert_raw, old_sig, old_public):
        raise AssertionError("missing valid prior-root countersignature")
    if not signature_valid(cert_raw, new_sig, new_public):
        raise AssertionError("missing valid successor proof of possession")
    cert = parse(cert_raw)
    expected = {
        "format": DOMAIN, "from_generation": 1, "to_generation": 2,
        "from_root_sha256": sha(old_public),
        "to_root_sha256": sha(new_public),
        "historical_v050_root_sha256": sha(historical_public),
        "v050_certificate_sha256": sha(historical_certificate),
        "scope": policy["scope"], "rotation": "DUAL_SIGNATURE",
        "lost_key": False, "compromised": False,
        "authorization": "NONE", "execution": "HOLD",
    }
    if (cert != expected
        or type(cert.get("from_generation")) is not int
        or type(cert.get("to_generation")) is not int
        or cert["to_generation"] < policy["minimum_root_generation"]):
        raise AssertionError("root custody handoff changed or revoked")
    return {"root_generation": 2, "custody": "DUAL_SIGNATURE_VERIFIED",
            "authorization": "NONE", "execution": "HOLD",
            "recovery": "STAGED_ONLY"}


def verify_all(cert: bytes, old_sig: bytes, new_sig: bytes,
               old_public: bytes, new_public: bytes, policy: dict,
               historical_public: bytes, historical_certificate: bytes) -> dict:
    result = verify_handoff(cert, old_sig, new_sig, old_public,
                            new_public, policy, historical_public,
                            historical_certificate)
    # Recheck existing v0.50 witness trust transition, not just custody.
    previous = parse(PREVIOUS.read_bytes())
    current = parse(CURRENT.read_bytes())
    witness_result = verify_root(
        BACKUP, HEAD.read_bytes(), parse(VOTES.read_bytes()),
        current, previous, WITNESS_CERT.read_bytes(),
        WITNESS_SIG.read_bytes(), WITNESS_PUBLIC.read_bytes(),
        parse(WITNESS_PIN.read_bytes()),
    )
    if (witness_result["root_transition"] != "VERIFIED"
        or result["execution"] != "HOLD"):
        raise AssertionError("root custody attempted authority")
    return result


def reject(inputs: tuple, reason: str) -> None:
    try:
        verify_handoff(*inputs)
    except (AssertionError, ValueError, TypeError, KeyError, OSError):
        return
    raise AssertionError("accepted unsafe root custody: " + reason)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing overwrite of custody fixture")
    ROOT.mkdir(mode=0o700, parents=True)
    old_private = ROOT / "prior-root-private.pem"
    new_private = ROOT / "successor-root-private.pem"
    for private, public in ((old_private, OLD_PUBLIC),
                            (new_private, NEW_PUBLIC)):
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        private.chmod(0o600)
        openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
    old_pub, new_pub = OLD_PUBLIC.read_bytes(), NEW_PUBLIC.read_bytes()
    historical_pub = WITNESS_PUBLIC.read_bytes()
    historical_cert = WITNESS_CERT.read_bytes()
    scope = parse(CURRENT.read_bytes())["scope"]
    cert = handoff(old_pub, new_pub, historical_pub, scope)
    raw = canonical(cert)
    old_sig = sign(old_private, raw)
    new_sig = sign(new_private, raw)
    policy = {
        "format": POLICY_DOMAIN, "minimum_root_generation": 2,
        "expected_old_root_sha256": sha(old_pub),
        "expected_new_root_sha256": sha(new_pub),
        "historical_v050_root_sha256": sha(historical_pub),
        "v050_certificate_sha256": sha(historical_cert), "scope": scope,
    }
    inputs = (raw, old_sig, new_sig, old_pub, new_pub, policy,
              historical_pub, historical_cert)
    if verify_all(*inputs)["custody"] != "DUAL_SIGNATURE_VERIFIED":
        raise AssertionError("valid custody handoff rejected")
    reject((raw, b"invalid", *inputs[2:]), "prior root missing")
    reject((raw, old_sig, b"invalid", *inputs[3:]), "successor root missing")
    reject((raw, new_sig, old_sig, *inputs[3:]), "crossed signatures")
    reject((canonical({**cert, "to_generation": 1}), *inputs[1:]),
           "unsigned root rollback")
    compromised = canonical({**cert, "compromised": True})
    reject((compromised, sign(old_private, compromised),
            sign(new_private, compromised), *inputs[3:]),
           "authentically signed compromised custody")
    lost = canonical({**cert, "lost_key": True})
    reject((lost, sign(old_private, lost), sign(new_private, lost),
            *inputs[3:]), "authentically signed lost-key transition")
    escalation = canonical({**cert, "execution": "ALLOW"})
    reject((escalation, sign(old_private, escalation),
            sign(new_private, escalation), *inputs[3:]),
           "dual-signed execution escalation")
    reject((*inputs[:5], {**policy, "minimum_root_generation": 3},
            *inputs[6:]), "receiver root floor advanced")
    reject((*inputs[:5], {**policy,
            "expected_old_root_sha256": "00" * 32},
            *inputs[6:]), "untrusted predecessor")
    reject((*inputs[:7], b"forged-history"),
           "historical root provenance changed")
    reject((*inputs[:5], {**policy, "scope": "foreign-scope"},
            *inputs[6:]), "unauthorized scope")
    old_private.unlink()
    new_private.unlink()
    CERT.write_bytes(raw)
    OLD_SIGNATURE.write_bytes(old_sig)
    NEW_SIGNATURE.write_bytes(new_sig)
    POLICY.write_bytes(canonical(policy))
    print("ORCHEASTRA v0.51: dual-signed CI root handoff, 11 hostile "
          "custody scenarios rejected; NONE/HOLD")


def verify_restart() -> None:
    if any(ROOT.glob("*private.pem")):
        raise AssertionError("ephemeral root signing key retained")
    result = verify_all(
        CERT.read_bytes(), OLD_SIGNATURE.read_bytes(),
        NEW_SIGNATURE.read_bytes(), OLD_PUBLIC.read_bytes(),
        NEW_PUBLIC.read_bytes(), parse(POLICY.read_bytes()),
        WITNESS_PUBLIC.read_bytes(), WITNESS_CERT.read_bytes(),
    )
    if result["root_generation"] != 2 or result["execution"] != "HOLD":
        raise AssertionError("root rotation did not survive restart")
    print("ORCHEASTRA v0.51: root custody proof verified after restart; HOLD")


def main() -> None:
    if sys.argv[1:2] == ["--verify-portable"]:
        if len(sys.argv) != 10:
            raise AssertionError("expected CERT OLD_SIG NEW_SIG OLD_PUBLIC NEW_PUBLIC POLICY HISTORY_PUBLIC HISTORY_CERT")
        result = verify_handoff(
            Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes(),
            Path(sys.argv[4]).read_bytes(), Path(sys.argv[5]).read_bytes(),
            Path(sys.argv[6]).read_bytes(), parse(Path(sys.argv[7]).read_bytes()),
            Path(sys.argv[8]).read_bytes(), Path(sys.argv[9]).read_bytes(),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated CI required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_restart()
    else:
        raise AssertionError("expected --create/--verify/--verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.51 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
