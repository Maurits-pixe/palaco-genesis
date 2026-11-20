#!/usr/bin/env python3
"""ORCHEASTRA v0.34 -- fail-closed, non-executing recovery disposition.

The CLI authenticates the v0.32 and v0.33 trust evidence before it
assesses recovery. Pure policy tests use explicitly labeled fixtures.
No execution capability, account token, network endpoint or signing.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import os
import sys

from orcheastra_policy_signed_checkpoint import verify_signature
from orcheastra_policy_trust_rotation import (
    LATEST, LATEST_SIG, NEXT_PUBLIC, verify_all,
)
from orcheastra_trust_registry_v033 import (
    DOCUMENT, DOMAIN, FIXTURE_CLOCK, HIGH_WATER, PUBLIC, SIGNATURE,
    instant, parse, verify_registry,
)


class RecoveryStatus(str, Enum):
    VERIFIED = "VERIFIED"
    STALE = "STALE"
    REVOKED = "REVOKED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class RecoveryDisposition:
    status: RecoveryStatus
    reason: str
    execution: str = "HOLD"

    def __post_init__(self) -> None:
        if self.execution != "HOLD":
            raise ValueError("recovery decisions never authorize execution")


def decision(
    registry: dict,
    high_water: dict,
    key_id: str,
    checkpoint_version: int,
    observed_digest: str,
    clock: datetime,
) -> RecoveryDisposition:
    """Classify policy *after* signature, lineage and DB-head verification.

    Calling this pure function with forged objects does not authenticate
    anything. Only trusted_recovery() checks signatures first.
    """
    deny = RecoveryDisposition
    if (not isinstance(registry, dict) or not isinstance(high_water, dict)
        or registry.get("format") != DOMAIN
        or type(registry.get("registry_version")) is not int
        or type(high_water.get("registry_version")) is not int
        or type(high_water.get("checkpoint_version")) is not int
        or not isinstance(key_id, str) or not key_id
        or type(checkpoint_version) is not int
        or not isinstance(observed_digest, str) or len(observed_digest) != 64
        or not isinstance(registry.get("checkpoint_digest"), str)
        or not isinstance(high_water.get("checkpoint_digest"), str)):
        return deny(RecoveryStatus.UNAVAILABLE, "incomplete trustworthy state")

    if registry["registry_version"] < high_water["registry_version"]:
        return deny(RecoveryStatus.STALE, "registry version below high-water")
    if registry["registry_version"] != high_water["registry_version"]:
        return deny(RecoveryStatus.UNAVAILABLE, "registry/high-water mismatch")
    if (registry["checkpoint_digest"] != high_water["checkpoint_digest"]
        or observed_digest != high_water["checkpoint_digest"]):
        return deny(RecoveryStatus.STALE, "checkpoint digest is not current")
    if checkpoint_version < high_water["checkpoint_version"]:
        return deny(RecoveryStatus.STALE, "checkpoint version below high-water")
    if checkpoint_version != high_water["checkpoint_version"]:
        return deny(RecoveryStatus.UNAVAILABLE, "future checkpoint not anchored")

    keys = registry.get("keys")
    if not isinstance(keys, dict):
        return deny(RecoveryStatus.UNAVAILABLE, "missing signing-key policy")
    record = keys.get(key_id)
    if not isinstance(record, dict):
        return deny(RecoveryStatus.UNAVAILABLE, "unknown signing key")
    status = record.get("status")
    if status in ("revoked", "expired"):
        return deny(RecoveryStatus.REVOKED, f"key status: {status}")
    if status != "active" or type(record.get("min_version")) is not int:
        return deny(RecoveryStatus.UNAVAILABLE, "invalid signing-key policy")
    if checkpoint_version < record["min_version"]:
        return deny(RecoveryStatus.STALE, "checkpoint below signing-key minimum")
    try:
        first = instant(record["not_before"])
        last = instant(record["not_after"])
    except (AssertionError, TypeError, ValueError, KeyError):
        return deny(RecoveryStatus.UNAVAILABLE, "invalid trusted validity window")
    if first >= last:
        return deny(RecoveryStatus.UNAVAILABLE, "inverted trusted validity window")
    if clock < first:
        return deny(RecoveryStatus.UNAVAILABLE, "signing key not yet valid")
    if clock >= last:
        return deny(RecoveryStatus.REVOKED, "signing key expired")
    return deny(RecoveryStatus.VERIFIED, "current authenticated audit evidence")


def trusted_recovery() -> RecoveryDisposition:
    """Verify pinned signatures and journal heads before a read-only result."""
    try:
        # Check rotation, anchored heads, and independently calculated DB state.
        rotated = verify_all()
        signed_registry, pinned = verify_registry()
        latest = LATEST.read_bytes()
        if not verify_signature(latest, LATEST_SIG.read_bytes(), NEXT_PUBLIC):
            raise AssertionError("checkpoint signature unavailable")
        if not verify_signature(DOCUMENT.read_bytes(), SIGNATURE.read_bytes(), PUBLIC):
            raise AssertionError("registry signature unavailable")
        expected_digest = hashlib.sha256(latest).hexdigest()
        # Comparison is mandatory even if cryptographic signatures verify.
        if (signed_registry.get("checkpoint_digest") != expected_digest
            or pinned.get("checkpoint_digest") != expected_digest):
            raise AssertionError("signed registry is not bound to the checkpoint")
        return decision(
            signed_registry, pinned, "successor-v2",
            rotated["version"], expected_digest, instant(FIXTURE_CLOCK),
        )
    except (OSError, ValueError, TypeError, KeyError, AssertionError):
        return RecoveryDisposition(
            RecoveryStatus.UNAVAILABLE, "independent trust validation failed",
        )


def matrix() -> None:
    """Test decisions with fixtures, not with untrusted simulated signatures."""
    observed = hashlib.sha256(LATEST.read_bytes()).hexdigest()
    registry, pin = verify_registry()
    clock = instant(FIXTURE_CLOCK)

    def check(status: RecoveryStatus, name: str, **overrides: object) -> None:
        arguments = {
            "registry": registry, "high_water": pin,
            "key_id": "successor-v2", "checkpoint_version": 2,
            "observed_digest": observed, "clock": clock,
        }
        arguments.update(overrides)
        result = decision(**arguments)
        if result.status is not status or result.execution != "HOLD":
            raise AssertionError(f"{name}: unexpected {result}")

    check(RecoveryStatus.VERIFIED, "valid historical checkpoint")
    check(RecoveryStatus.REVOKED, "revoked key", key_id="retired-v1")
    check(RecoveryStatus.REVOKED, "expired key", key_id="expired-v3")
    check(RecoveryStatus.UNAVAILABLE, "unknown key", key_id="missing")
    check(RecoveryStatus.STALE, "old checkpoint", checkpoint_version=1)
    check(RecoveryStatus.STALE, "digest rollback", observed_digest="00" * 32)
    check(RecoveryStatus.STALE, "old registry",
          registry={**registry, "registry_version": 2})
    check(RecoveryStatus.UNAVAILABLE, "missing high-water", high_water={})
    check(RecoveryStatus.UNAVAILABLE, "future checkpoint", checkpoint_version=3)
    check(RecoveryStatus.REVOKED, "expired active key",
          clock=instant("2028-01-01T00:00:00Z"))
    check(RecoveryStatus.UNAVAILABLE, "pre-validity",
          clock=instant("2025-01-01T00:00:00Z"))
    check(RecoveryStatus.UNAVAILABLE, "unknown status",
          registry={**registry, "keys": {
              **registry["keys"],
              "successor-v2": {
                  **registry["keys"]["successor-v2"], "status": "unknown",
              },
          }})
    if trusted_recovery().status != RecoveryStatus.VERIFIED:
        raise AssertionError("authentic trust evidence was rejected")
    print("ORCHEASTRA v0.34: 12 classifications + authenticated HOLD PASS")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("only isolated loopback CI PostgreSQL permitted")
    if sys.argv[1:] == ["--test"]:
        matrix()
    elif sys.argv[1:] == ["--verify"]:
        result = trusted_recovery()
        print(json.dumps({"status": result.status.value,
                          "execution": result.execution, "reason": result.reason},
                         sort_keys=True))
        if result.status is not RecoveryStatus.VERIFIED:
            raise AssertionError("recovery validation failed closed")
    else:
        raise AssertionError("expected --test or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, OSError) as error:
        print(f"ORCHEASTRA v0.34 failed: {error}", file=sys.stderr)
        sys.exit(1)
