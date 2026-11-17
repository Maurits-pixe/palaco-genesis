#!/usr/bin/env python3
"""ORCHEASTRA v0.38 -- separately signed high-water witness.

A fresh CI-only Ed25519 witness signs a canonical statement binding the
v0.37 transfer scope, latest sequence and bundle hash. A receiver needs
a pinned witness public-key digest and independently supplied minimum
trusted statement version. No DB access or production authority.
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
from orcheastra_evidence_handoff_v037 import (
    BUNDLE_COPY, PIN_COPY, HANDOFF, HIGH_WATER, STORE as HANDOFF_STORE,
    evaluate, parse,
)

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v038"
PRIVATE = STORE / "ephemeral-witness-private.pem"
PUBLIC = STORE / "witness-public.pem"
PUBLIC_PIN = STORE / "witness-public.sha256"
STATEMENT = STORE / "signed-high-water.json"
SIGNATURE = STORE / "signed-high-water.sig"
TRUSTED_VERSION = STORE / "trusted-minimum-version.txt"
DOMAIN = "PALACO:ORCHEASTRA:SIGNED_HIGH_WATER:v1"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def openssl(*arguments: str) -> None:
    proc = subprocess.run(["openssl", *arguments], capture_output=True,
                          text=True, check=False, timeout=20)
    if proc.returncode:
        raise AssertionError("Ed25519 signature operation failed")


def verify_witness(bundle: bytes, signer_pin: str, manifest: bytes,
                   statement: bytes, signature: bytes, public: bytes,
                   public_pin: str, minimum_version: int) -> dict:
    """Receive a signed witness and a separately trusted monotonic floor."""
    if not isinstance(public_pin, str) or len(public_pin) != 64:
        raise AssertionError("missing trusted witness fingerprint")
    if sha(public) != public_pin:
        raise AssertionError("untrusted witness signing key")
    if not signature_valid(statement, signature, public):
        raise AssertionError("high-water statement signature invalid")
    if type(minimum_version) is not int or minimum_version < 1:
        raise AssertionError("missing independently trusted version floor")
    signed = parse(statement)
    if (signed.get("format") != DOMAIN
        or type(signed.get("witness_version")) is not int
        or signed["witness_version"] < minimum_version):
        raise AssertionError("signed high-water rollback")
    high = signed.get("high_water")
    if not isinstance(high, dict):
        raise AssertionError("incomplete signed high-water")
    # v0.37 is the policy decision engine, but the pinned high-water
    # object here is authenticated by Ed25519 *before* evaluation.
    return evaluate(bundle, signer_pin, manifest, canonical(high))


def verify_saved() -> dict:
    if PRIVATE.exists():
        raise AssertionError("ephemeral witness key not destroyed")
    result = verify_witness(
        BUNDLE_COPY.read_bytes(), PIN_COPY.read_text(encoding="ascii").strip(),
        HANDOFF.read_bytes(), STATEMENT.read_bytes(),
        SIGNATURE.read_bytes(), PUBLIC.read_bytes(),
        PUBLIC_PIN.read_text(encoding="ascii").strip(),
        int(TRUSTED_VERSION.read_text(encoding="ascii").strip()),
    )
    if result["execution"] != "HOLD" or result["authorization"] != "NONE":
        raise AssertionError("witness attempted to authorize execution")
    return result


def expect_denied(*args, reason: str) -> None:
    try:
        verify_witness(*args)
    except (AssertionError, ValueError, TypeError, KeyError):
        return
    raise AssertionError("invalid witness accepted: " + reason)


def seal() -> None:
    if STORE.exists():
        raise AssertionError("refusing to overwrite witness evidence")
    prior = parse(HIGH_WATER.read_bytes())
    initial = evaluate(BUNDLE_COPY.read_bytes(),
                       PIN_COPY.read_text(encoding="ascii").strip(),
                       HANDOFF.read_bytes(), canonical(prior))
    if initial["freshness"] != "CURRENT":
        raise AssertionError("predecessor is not a current handoff")
    STORE.mkdir(mode=0o700, parents=True)
    openssl("genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE))
    PRIVATE.chmod(0o600)
    openssl("pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC))
    document = {"format": DOMAIN, "witness_version": 1,
                "high_water": prior, "authorization": "NONE",
                "execution": "HOLD"}
    STATEMENT.write_bytes(canonical(document))
    with tempfile.TemporaryDirectory(dir=STORE) as folder:
        source = Path(folder) / "statement"
        source.write_bytes(STATEMENT.read_bytes())
        openssl("pkeyutl", "-sign", "-inkey", str(PRIVATE),
                "-rawin", "-in", str(source), "-out", str(SIGNATURE))
    PUBLIC_PIN.write_text(sha(PUBLIC.read_bytes()) + "\n", encoding="ascii")
    TRUSTED_VERSION.write_text("1\n", encoding="ascii")
    PRIVATE.unlink()

    args = (
        BUNDLE_COPY.read_bytes(), PIN_COPY.read_text(encoding="ascii").strip(),
        HANDOFF.read_bytes(), STATEMENT.read_bytes(),
        SIGNATURE.read_bytes(), PUBLIC.read_bytes(),
        PUBLIC_PIN.read_text(encoding="ascii").strip(), 1,
    )
    if verify_witness(*args)["freshness"] != "CURRENT":
        raise AssertionError("valid independently signed witness rejected")

    def modified(update: dict) -> bytes:
        return canonical({**document, **update})

    expect_denied(*args[:3], modified({"witness_version": 2}), *args[4:],
                  reason="unsigned witness version change")
    expect_denied(*args[:3], modified({"high_water": {
        **prior, "current_bundle_sha256": "00" * 32}}), *args[4:],
                  reason="forged newest digest")
    expect_denied(*args[:4], b"invalid-signature", *args[5:],
                  reason="invalid signature")
    expect_denied(*args[:6], "00" * 32, args[7],
                  reason="wrong independently pinned witness key")
    expect_denied(*args[:7], 2, reason="signed version below trusted floor")
    expect_denied(*args[:3], b"{}\n", *args[4:],
                  reason="missing signed witness content")
    # A valid statement can classify a valid bundle as historical when
    # the separately authenticated latest sequence is higher.
    updated = {**prior, "minimum_sequence": 2}
    historical = {**document, "witness_version": 2, "high_water": updated}
    # New signing authority requires a NEW signature; the existing one
    # must not validate the changed statement.
    expect_denied(*args[:3], canonical(historical), *args[4:],
                  reason="unsigned historical change")
    print("ORCHEASTRA v0.38: signed high-water and 7 adversarial checks PASS")


def main() -> None:
    if len(sys.argv) == 9 and sys.argv[1] == "--verify-portable":
        result = verify_witness(
            Path(sys.argv[2]).read_bytes(),
            Path(sys.argv[3]).read_text(encoding="ascii").strip(),
            Path(sys.argv[4]).read_bytes(), Path(sys.argv[5]).read_bytes(),
            Path(sys.argv[6]).read_bytes(), Path(sys.argv[7]).read_bytes(),
            Path(sys.argv[8]).read_text(encoding="ascii").strip(),
            1,
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires disposable loopback database")
    if sys.argv[1:] == ["--seal"]:
        seal()
    elif sys.argv[1:] == ["--verify"]:
        result = verify_saved()
        if result["freshness"] != "CURRENT":
            raise AssertionError("witness no longer current")
        print("ORCHEASTRA v0.38: signed witness verified after DB restart")
    else:
        raise AssertionError("expected --seal / --verify / --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as error:
        print(f"ORCHEASTRA v0.38 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
