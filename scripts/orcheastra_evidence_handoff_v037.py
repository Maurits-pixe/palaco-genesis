#!/usr/bin/env python3
"""ORCHEASTRA v0.37 -- portable handoff and external freshness policy.

Demonstrates a transfer manifest for signed v0.36 evidence, with a separately
pinned high-water policy. A valid historical signature is not proof that the
bundle is current. This runner-local fixture does not provide durable storage,
trusted time, off-host witnessing or operational authority.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_recovery_bundle_v036 import ARCHIVE, PIN, verify_bundle

STORE = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v037"
HANDOFF = STORE / "handoff.json"
HIGH_WATER = STORE / "independent-high-water.json"
BUNDLE_COPY = STORE / "historical-evidence.zip"
PIN_COPY = STORE / "trusted-report-signer.sha256"
DOMAIN = "PALACO:ORCHEASTRA:EVIDENCE_HANDOFF:v1"
POLICY_DOMAIN = "PALACO:ORCHEASTRA:RETENTION_POLICY:v1"
OBSERVED_FIXTURE = "2026-11-17T12:00:00Z"


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse(raw: bytes) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical(value) != raw:
        raise AssertionError("non-canonical evidence policy")
    return value


def evaluate(raw_bundle: bytes, signer_pin: str, manifest_raw: bytes,
             high_water_raw: bytes) -> dict:
    """Verify signature/contents, then separately assess CURRENT vs HISTORICAL.

    All 'current' claims depend on the independently supplied high-water file.
    This is NOT an authenticator for the high-water file itself; its integrity
    is an out-of-band precondition.
    """
    report = verify_bundle(raw_bundle, signer_pin)
    handoff = parse(manifest_raw)
    pin = parse(high_water_raw)
    if (handoff.get("format") != DOMAIN
        or handoff.get("bundle_sha256") != sha(raw_bundle)
        or handoff.get("signer_sha256") != signer_pin
        or handoff.get("scope") != report.get("scope")
        or handoff.get("authorization") != "NONE"
        or handoff.get("execution") != "HOLD"):
        raise AssertionError("handoff does not bind to verified evidence")
    retention = handoff.get("retention")
    if (not isinstance(retention, dict)
        or retention.get("format") != POLICY_DOMAIN
        or retention.get("preserve_original") is not True
        or retention.get("deletion_allowed") is not False
        or retention.get("automatic_purge") is not False
        or retention.get("retention_class") != "CI_FIXTURE_NO_ARCHIVE"
        or retention.get("review_required_for_disposal") is not True):
        raise AssertionError("unsupported retention or deletion policy")
    if (pin.get("format") != DOMAIN
        or pin.get("scope") != handoff["scope"]
        or pin.get("signer_sha256") != signer_pin
        or type(pin.get("minimum_sequence")) is not int
        or type(handoff.get("sequence")) is not int
        or pin["minimum_sequence"] < 1 or handoff["sequence"] < 1):
        raise AssertionError("independent high-water unavailable or invalid")
    if handoff["sequence"] > pin["minimum_sequence"]:
        raise AssertionError("future checkpoint without independent witness")
    if handoff["sequence"] < pin["minimum_sequence"]:
        status = "HISTORICAL"
    elif pin.get("current_bundle_sha256") != sha(raw_bundle):
        status = "HISTORICAL"
    else:
        status = "CURRENT"
    return {
        "signature": "VERIFIED",
        "freshness": status,
        "read_only": True,
        "authorization": "NONE",
        "execution": "HOLD",
    }


def rejects(bundle: bytes, pin: str, handoff: bytes,
            high_water: bytes, label: str) -> None:
    try:
        evaluate(bundle, pin, handoff, high_water)
    except (AssertionError, ValueError, TypeError, KeyError):
        return
    raise AssertionError("invalid transfer accepted: " + label)


def create() -> None:
    if STORE.exists():
        raise AssertionError("refuse to overwrite existing handoff")
    raw = ARCHIVE.read_bytes()
    key_pin = PIN.read_text(encoding="ascii").strip()
    report = verify_bundle(raw, key_pin)
    STORE.mkdir(parents=True, mode=0o700)
    BUNDLE_COPY.write_bytes(raw)
    PIN_COPY.write_text(key_pin + "\n", encoding="ascii")
    manifest = {
        "format": DOMAIN,
        "scope": report["scope"],
        "sequence": 1,
        "bundle_sha256": sha(raw),
        "signer_sha256": key_pin,
        "authorization": "NONE",
        "execution": "HOLD",
        "retention": {
            "format": POLICY_DOMAIN,
            "retention_class": "CI_FIXTURE_NO_ARCHIVE",
            "preserve_original": True,
            "deletion_allowed": False,
            "automatic_purge": False,
            "review_required_for_disposal": True,
        },
    }
    HIGH_WATER.write_bytes(canonical({
        "format": DOMAIN, "scope": report["scope"],
        "minimum_sequence": 1, "current_bundle_sha256": sha(raw),
        "signer_sha256": key_pin,
    }))
    HANDOFF.write_bytes(canonical(manifest))
    outcome = evaluate(raw, key_pin, HANDOFF.read_bytes(),
                       HIGH_WATER.read_bytes())
    if outcome["freshness"] != "CURRENT" or outcome["execution"] != "HOLD":
        raise AssertionError("initial handoff rejected")
    # Historical signature remains valid, but pinned newest sequence
    # forces a different freshness result without altering the bundle.
    updated = parse(HIGH_WATER.read_bytes())
    updated["minimum_sequence"] = 2
    historical = evaluate(raw, key_pin, HANDOFF.read_bytes(),
                          canonical(updated))
    if historical["freshness"] != "HISTORICAL":
        raise AssertionError("older valid evidence classified current")
    # Equally sequenced but DIFFERENT trusted head also must be historical.
    altered_pin = {**updated, "minimum_sequence": 1,
                   "current_bundle_sha256": "00" * 32}
    if evaluate(raw, key_pin, HANDOFF.read_bytes(),
                canonical(altered_pin))["freshness"] != "HISTORICAL":
        raise AssertionError("mismatched latest head was accepted")
    rejects(raw, key_pin, HANDOFF.read_bytes(),
            canonical({**updated, "minimum_sequence": 0}),
            "missing trustworthy high-water")
    rejects(raw, key_pin, HANDOFF.read_bytes(),
            canonical({**updated, "minimum_sequence": -1}),
            "negative high-water")
    rejects(raw, key_pin, HANDOFF.read_bytes(), b"{}\n",
            "missing witness manifest")
    rejects(raw, key_pin, canonical({**manifest, "bundle_sha256": "00" * 32}),
            HIGH_WATER.read_bytes(), "changed bundle digest")
    rejects(raw, key_pin, canonical({**manifest, "execution": "ALLOW"}),
            HIGH_WATER.read_bytes(), "attempted execution")
    rejects(raw, key_pin, canonical({
        **manifest, "retention": {**manifest["retention"], "automatic_purge": True}
    }), HIGH_WATER.read_bytes(), "silent evidence purge")
    rejects(raw, "00" * 32, HANDOFF.read_bytes(),
            HIGH_WATER.read_bytes(), "invalid signer pin")
    print("ORCHEASTRA v0.37: portable handoff, retention and stale-vs-current PASS")


def verify() -> None:
    result = evaluate(
        BUNDLE_COPY.read_bytes(),
        PIN_COPY.read_text(encoding="ascii").strip(),
        HANDOFF.read_bytes(), HIGH_WATER.read_bytes(),
    )
    if result != {
        "signature": "VERIFIED", "freshness": "CURRENT",
        "read_only": True, "authorization": "NONE", "execution": "HOLD",
    }:
        raise AssertionError("handoff not reproducible after restart")
    print("ORCHEASTRA v0.37: pinned handoff still CURRENT after PostgreSQL restart")


def main() -> None:
    # Portable mode works without DB configuration. The high-water file
    # must be independently authenticated by the receiving organization.
    if len(sys.argv) == 6 and sys.argv[1] == "--verify-portable":
        result = evaluate(
            Path(sys.argv[2]).read_bytes(),
            Path(sys.argv[3]).read_text(encoding="ascii").strip(),
            Path(sys.argv[4]).read_bytes(),
            Path(sys.argv[5]).read_bytes(),
        )
        print(json.dumps(result, sort_keys=True))
        return
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("requires disposable loopback PostgreSQL")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify()
    else:
        raise AssertionError("expected --create, --verify or --verify-portable")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, TypeError,
            KeyError) as exc:
        print(f"ORCHEASTRA v0.37 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
