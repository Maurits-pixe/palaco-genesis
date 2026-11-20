#!/usr/bin/env python3
"""ORCHEASTRA v0.47: signed, portable recovery-head witness fixture.

The CI runner signs a v0.46 backup/head binding with a *separate*
ephemeral Ed25519 recovery identity. The receiver must supply the trusted
public-key fingerprint and monotonically retained minimum version OUTSIDE
the backup. This does not create an external witness service.
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

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v047"
PRIVATE = ROOT / "temporary-recovery-signing-key.pem"
PUBLIC = ROOT / "recovery-witness-public.pem"
STATEMENT = ROOT / "signed-recovery-anchor.json"
SIGNATURE = ROOT / "signed-recovery-anchor.sig"
TRUST = ROOT / "independent-receiver-trust.json"
HISTORICAL = ROOT / "historical-recovery-anchor.json"
HISTORICAL_SIG = ROOT / "historical-recovery-anchor.sig"
DOMAIN = "PALACO:ORCHEASTRA:EXTERNAL_RECOVERY_ANCHOR:v1"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run_openssl(*args: str) -> None:
    result = subprocess.run(["openssl", *args], check=False,
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise AssertionError("OpenSSL Ed25519 operation failed")


def sign(payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        raw_path = Path(folder) / "payload.json"
        signed_path = Path(folder) / "signature.bin"
        raw_path.write_bytes(payload)
        run_openssl("pkeyutl", "-sign", "-inkey", str(PRIVATE),
                    "-rawin", "-in", str(raw_path), "-out", str(signed_path))
        return signed_path.read_bytes()


def verify_portable(backup: Path, head_raw: bytes, statement_raw: bytes,
                    signature: bytes, public: bytes, trusted: dict) -> dict:
    """Validate recovery offline, without the original live database."""
    if (not isinstance(trusted, dict)
        or set(trusted) != {"format", "public_key_sha256",
                           "minimum_sequence", "required_scope"}
        or trusted["format"] != DOMAIN
        or type(trusted["minimum_sequence"]) is not int
        or trusted["minimum_sequence"] < 1
        or not isinstance(trusted["public_key_sha256"], str)
        or len(trusted["public_key_sha256"]) != 64
        or sha(public) != trusted["public_key_sha256"]):
        raise AssertionError("independent trusted signer or version unavailable")
    if not signature_valid(statement_raw, signature, public):
        raise AssertionError("unsigned or modified recovery anchor")
    statement = parse(statement_raw)
    if (set(statement) != {"format", "sequence", "head_sha256",
                           "backup_sha256", "scope", "state",
                           "authorization", "execution"}
        or statement["format"] != DOMAIN
        or type(statement["sequence"]) is not int
        or statement["sequence"] < trusted["minimum_sequence"]
        or statement["scope"] != trusted["required_scope"]
        or statement["state"] != "VERIFIED_HOLD"
        or statement["authorization"] != "NONE"
        or statement["execution"] != "HOLD"):
        raise AssertionError("recovery version rollback, scope, or authority violation")
    if sha(head_raw) != statement["head_sha256"]:
        raise AssertionError("recovery head changed after witness signature")
    if not backup.is_file() or sha(backup.read_bytes()) != statement["backup_sha256"]:
        raise AssertionError("signed backup digest mismatch")
    head = parse(head_raw)
    if head.get("scope") != statement["scope"]:
        raise AssertionError("recovery high-water scope mismatch")
    result = verify_backup(backup, head_raw, statement["head_sha256"])
    if result["recovery"] != "STAGED_ONLY" or result["execution"] != "HOLD":
        raise AssertionError("recovery cannot grant activation")
    return {**result, "signature": "VERIFIED",
            "trusted_sequence": statement["sequence"],
            "offline": True}


def reject(backup, head, stmt, sig, pub, trust, label):
    try:
        verify_portable(backup, head, stmt, sig, pub, trust)
    except (AssertionError, ValueError, KeyError, TypeError, OSError):
        return
    raise AssertionError("unsafe recovery witness accepted: " + label)


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refuse to overwrite recovery witness evidence")
    ROOT.mkdir(mode=0o700, parents=True)
    head = HEAD.read_bytes()
    source = parse(head)
    if verify_backup(BACKUP, head, sha(head))["status"] != "VERIFIED_HOLD":
        raise AssertionError("predecessor recovery head invalid")
    run_openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    run_openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC))
    binding = {
        "format": DOMAIN, "sequence": 2,
        "head_sha256": sha(head), "backup_sha256": sha(BACKUP.read_bytes()),
        "scope": source["scope"], "state": "VERIFIED_HOLD",
        "authorization": "NONE", "execution": "HOLD",
    }
    trusted = {
        "format": DOMAIN, "public_key_sha256": sha(PUBLIC.read_bytes()),
        "minimum_sequence": 2, "required_scope": source["scope"],
    }
    STATEMENT.write_bytes(canonical(binding))
    SIGNATURE.write_bytes(sign(STATEMENT.read_bytes()))
    old = {**binding, "sequence": 1}
    HISTORICAL.write_bytes(canonical(old))
    HISTORICAL_SIG.write_bytes(sign(HISTORICAL.read_bytes()))
    PRIVATE.unlink()
    TRUST.write_bytes(canonical(trusted))

    args = (BACKUP, head, STATEMENT.read_bytes(), SIGNATURE.read_bytes(),
            PUBLIC.read_bytes(), trusted)
    verified = verify_portable(*args)
    if verified["trusted_sequence"] != 2:
        raise AssertionError("expected pinned v0.47 signed head")
    # A genuine old signature cannot be used once the receiver has seen v2.
    reject(BACKUP, head, HISTORICAL.read_bytes(), HISTORICAL_SIG.read_bytes(),
           PUBLIC.read_bytes(), trusted, "valid historical signed anchor")
    reject(BACKUP, head, STATEMENT.read_bytes() + b" ", SIGNATURE.read_bytes(),
           PUBLIC.read_bytes(), trusted, "modified signed statement")
    reject(BACKUP, head, STATEMENT.read_bytes(), b"broken",
           PUBLIC.read_bytes(), trusted, "forged signature")
    reject(BACKUP, head, STATEMENT.read_bytes(), SIGNATURE.read_bytes(),
           PUBLIC.read_bytes(), {**trusted, "public_key_sha256": "00" * 32},
           "untrusted witness public key")
    reject(BACKUP, head, STATEMENT.read_bytes(), SIGNATURE.read_bytes(),
           PUBLIC.read_bytes(), {**trusted, "minimum_sequence": 3},
           "independent version floor advanced")
    reject(BACKUP, canonical({**source, "nonce_sha256": "00" * 32}),
           STATEMENT.read_bytes(), SIGNATURE.read_bytes(), PUBLIC.read_bytes(),
           trusted, "changed recovery head")
    tampered = ROOT / "tampered-copy.sqlite3"
    shutil.copyfile(BACKUP, tampered)
    with tampered.open("r+b") as file:
        file.seek(0)
        file.write(b"X")
    reject(tampered, head, STATEMENT.read_bytes(), SIGNATURE.read_bytes(),
           PUBLIC.read_bytes(), trusted, "corrupt backup")
    reject(ROOT / "missing.sqlite3", head, STATEMENT.read_bytes(),
           SIGNATURE.read_bytes(), PUBLIC.read_bytes(), trusted, "missing backup")
    reject(BACKUP, head, HISTORICAL.read_bytes(), HISTORICAL_SIG.read_bytes(),
           PUBLIC.read_bytes(), {**trusted, "required_scope": "wrong-scope"},
           "scope substitution")
    print("ORCHEASTRA v0.47: Ed25519 signed recovery anchor, offline "
          "minimum-version enforcement, 9 negative cases PASS")


def verify() -> None:
    if PRIVATE.exists():
        raise AssertionError("ephemeral recovery private key retained")
    result = verify_portable(
        BACKUP, HEAD.read_bytes(), STATEMENT.read_bytes(),
        SIGNATURE.read_bytes(), PUBLIC.read_bytes(),
        parse(TRUST.read_bytes()),
    )
    if result["trusted_sequence"] != 2:
        raise AssertionError("recovery witness version changed on restart")
    print("ORCHEASTRA v0.47: offline signed recovery head intact after restart")


def main() -> None:
    # Portable mode accepts every trust input explicitly, not from the bundle.
    if len(sys.argv) == 8 and sys.argv[1] == "--verify-portable":
        result = verify_portable(
            Path(sys.argv[2]), Path(sys.argv[3]).read_bytes(),
            Path(sys.argv[4]).read_bytes(), Path(sys.argv[5]).read_bytes(),
            Path(sys.argv[6]).read_bytes(), parse(Path(sys.argv[7]).read_bytes()),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("isolated loopback CI is mandatory")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create/--verify/--verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError,
            OSError, subprocess.TimeoutExpired) as error:
        print(f"ORCHEASTRA v0.47 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
