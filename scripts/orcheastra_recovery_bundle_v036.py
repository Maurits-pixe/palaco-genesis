#!/usr/bin/env python3
"""ORCHEASTRA v0.36: portable, Ed25519-signed recovery evidence bundle.

The ZIP carries a canonical v0.35 report and exact allowlisted public
evidence bytes. Verification needs an independently pinned SHA-256 digest
of the signer public key, supplied OUTSIDE the bundle. No secret keys,
credentials, network access or task execution are involved.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_report_v035 import EVIDENCE, REPORT, DIGEST_FILE, validate

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v036"
PRIVATE = ROOT / "ephemeral-report-signer.pem"
PUBLIC = ROOT / "trusted-report-signer.pem"
PIN = ROOT / "trusted-public-key.sha256"
ARCHIVE = ROOT / "recovery-evidence-v036.zip"
DOMAIN = "PALACO:ORCHEASTRA:SIGNED_RECOVERY_BUNDLE:v1"
REPORT_NAME = "report/recovery-report.json"
SIGNATURE_NAME = "report/recovery-report.sig"
PUBLIC_NAME = "keys/report-signer-public.pem"
MANIFEST_NAME = "manifest.json"
MAX_BUNDLE_BYTES = 2_000_000
MAX_FILE_BYTES = 300_000


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def openssl(*args: str, allow_failure: bool = False) -> bool:
    result = subprocess.run(
        ["openssl", *args], capture_output=True, text=True,
        check=False, timeout=20,
    )
    if not allow_failure and result.returncode:
        raise AssertionError("OpenSSL signing or verification failed")
    return result.returncode == 0


def signature_valid(report: bytes, signature: bytes, public: bytes) -> bool:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "report").write_bytes(report)
        (root / "signature").write_bytes(signature)
        (root / "public").write_bytes(public)
        return openssl(
            "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "public"),
            "-rawin", "-in", str(root / "report"),
            "-sigfile", str(root / "signature"), allow_failure=True,
        )


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            metadata = zipfile.ZipInfo(name, date_time=(2026, 11, 17, 0, 0, 0))
            metadata.compress_type = zipfile.ZIP_DEFLATED
            metadata.external_attr = 0o600 << 16
            archive.writestr(metadata, data)
    return output.getvalue()


def verify_bundle(raw_zip: bytes, pinned_public_digest: str) -> dict:
    if len(raw_zip) > MAX_BUNDLE_BYTES:
        raise AssertionError("bundle exceeds allowed limit")
    expected_evidence = {
        f"evidence/{name}.bin" for name in EVIDENCE
    }
    expected_names = expected_evidence | {
        REPORT_NAME, SIGNATURE_NAME, PUBLIC_NAME, MANIFEST_NAME
    }
    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise AssertionError("missing, extra or duplicated bundle entries")
        if any(member.file_size <= 0 or member.file_size > MAX_FILE_BYTES
               for member in members):
            raise AssertionError("bundle entry violates size policy")
        entries = {name: archive.read(name) for name in names}

    if digest(entries[PUBLIC_NAME]) != pinned_public_digest:
        raise AssertionError("public signer is not independently pinned")
    if not signature_valid(
        entries[REPORT_NAME], entries[SIGNATURE_NAME], entries[PUBLIC_NAME]
    ):
        raise AssertionError("recovery report signature invalid")

    report_raw = entries[REPORT_NAME]
    report = json.loads(report_raw)
    if not isinstance(report, dict) or canonical(report) != report_raw:
        raise AssertionError("report canonical encoding invalid")
    if (report.get("authorization") != "NONE"
        or report.get("execution") != "HOLD"
        or not isinstance(report.get("decision"), dict)
        or report["decision"].get("execution") != "HOLD"
        or report["decision"].get("status") != "VERIFIED"):
        raise AssertionError("bundle attempts to elevate recovery privileges")

    manifest_raw = entries[MANIFEST_NAME]
    manifest = json.loads(manifest_raw)
    if not isinstance(manifest, dict) or canonical(manifest) != manifest_raw:
        raise AssertionError("manifest is not canonical")
    if (manifest.get("format") != DOMAIN
        or manifest.get("report_sha256") != digest(report_raw)
        or manifest.get("evidence") != report.get("evidence")
        or set(report.get("evidence", {})) != set(EVIDENCE)):
        raise AssertionError("report and manifest are inconsistent")

    for identifier in EVIDENCE:
        evidence = entries[f"evidence/{identifier}.bin"]
        item = report["evidence"][identifier]
        if (not isinstance(item, dict)
            or item.get("size_bytes") != len(evidence)
            or item.get("sha256") != digest(evidence)):
            raise AssertionError(f"evidence mismatch: {identifier}")
    return report


def reject(entries: dict[str, bytes], pin: str, reason: str) -> None:
    try:
        verify_bundle(zip_bytes(entries), pin)
    except (AssertionError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        return
    raise AssertionError(f"invalid evidence bundle was accepted: {reason}")


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refusing to overwrite signed evidence bundle")
    raw_report = REPORT.read_bytes()
    recorded_digest = DIGEST_FILE.read_text(encoding="ascii").strip()
    verified = validate(raw_report, recorded_digest)
    ROOT.mkdir(mode=0o700, parents=True)
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC))
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        filename = Path(folder) / "report.json"
        filename.write_bytes(raw_report)
        signature = Path(folder) / "report.sig"
        openssl(
            "pkeyutl", "-sign", "-inkey", str(PRIVATE),
            "-rawin", "-in", str(filename), "-out", str(signature),
        )
        entries = {
            REPORT_NAME: raw_report,
            SIGNATURE_NAME: signature.read_bytes(),
            PUBLIC_NAME: PUBLIC.read_bytes(),
            MANIFEST_NAME: canonical({
                "format": DOMAIN,
                "report_sha256": digest(raw_report),
                "evidence": verified["evidence"],
                "retention": {
                    "scope": "ephemeral-ci-only",
                    "policy": "no production archive or external witness",
                },
            }),
        }
        entries.update({
            f"evidence/{name}.bin": path.read_bytes()
            for name, path in EVIDENCE.items()
        })
    # Private key must never reach the export archive or its verifier.
    PRIVATE.unlink()
    PIN.write_text(digest(entries[PUBLIC_NAME]) + "\n", encoding="ascii")
    ARCHIVE.write_bytes(zip_bytes(entries))
    verify_bundle(ARCHIVE.read_bytes(), PIN.read_text().strip())

    changed = dict(entries)
    changed[REPORT_NAME] = changed[REPORT_NAME].replace(
        b'"execution":"HOLD"', b'"execution":"ALLOW"', 1
    )
    reject(changed, PIN.read_text().strip(), "altered execution disposition")
    changed = dict(entries)
    changed["evidence/registry_signature_v033.bin"] += b"altered"
    reject(changed, PIN.read_text().strip(), "modified evidence")
    changed = dict(entries)
    del changed["evidence/registry_signature_v033.bin"]
    reject(changed, PIN.read_text().strip(), "missing evidence")
    changed = dict(entries)
    changed[MANIFEST_NAME] = changed[MANIFEST_NAME].replace(
        b'"report_sha256":"', b'"report_sha256":"0', 1
    )
    reject(changed, PIN.read_text().strip(), "forged manifest")
    reject(entries, "00" * 32, "incorrect external key pin")
    print(f"ORCHEASTRA v0.36: portable signed report + {len(EVIDENCE)} proofs; 5 attacks rejected")


def verify() -> None:
    if PRIVATE.exists():
        raise AssertionError("private signer key retained")
    pin = PIN.read_text(encoding="ascii").strip()
    if len(pin) != 64:
        raise AssertionError("trusted public key pin malformed")
    report = verify_bundle(ARCHIVE.read_bytes(), pin)
    if report != validate(REPORT.read_bytes(), DIGEST_FILE.read_text().strip()):
        raise AssertionError("portable report differs from trusted current audit")
    print("ORCHEASTRA v0.36: signed portable bundle and current DB evidence PASS")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("ephemeral loopback PostgreSQL is required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        print(f"ORCHEASTRA v0.36 failed: {error}", file=sys.stderr)
        sys.exit(1)
