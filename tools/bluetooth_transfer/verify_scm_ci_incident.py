"""PALACO v6.1 independent-process CI incident verifier (DRAFT / HOLD).

This verifies structural integrity and one-time local consumption only.
It does NOT authenticate the producer: an attacker can recompute bare SHA-256.
No signatures, hardware attestation, trusted timestamp or release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

CANONICAL = b"PALACO-BT-CI-INCIDENT-V1|WORKER_FAULTED|HOLD|DENY"
EXPECTED_HASH = hashlib.sha256(CANONICAL).hexdigest()
EXPECTED_KEYS = frozenset({
    "protocol", "incident", "decision", "authorization",
    "canonical_sha256", "independent_signature", "native_security_verified"
})


class EvidenceRejected(ValueError):
    """Deterministic refusal. Never contains the untrusted evidence body."""


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceRejected("duplicate JSON field")
        result[key] = value
    return result


def verify_bytes(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > 4096:
        raise EvidenceRejected("empty or oversized evidence")
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=strict_object,
            parse_constant=lambda _: (_ for _ in ()).throw(EvidenceRejected("nonfinite value"))
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceRejected("malformed incident evidence") from exc
    if not isinstance(document, dict) or set(document) != EXPECTED_KEYS:
        raise EvidenceRejected("missing or extra evidence fields")
    expected_values = {
        "protocol": "PALACO-BT-CI-INCIDENT-V1",
        "incident": "WORKER_FAULTED",
        "decision": "HOLD",
        "authorization": "DENY",
        "canonical_sha256": EXPECTED_HASH,
        "independent_signature": False,
        "native_security_verified": False,
    }
    for key, expected in expected_values.items():
        if type(document[key]) is not type(expected) or document[key] != expected:
            raise EvidenceRejected("invalid evidence field")
    return document


def verify_once(input_file: Path, receipt_file: Path) -> None:
    if not input_file.is_file() or input_file.is_symlink():
        raise EvidenceRejected("evidence missing or unsafe path")
    if receipt_file.exists() or receipt_file.is_symlink():
        raise EvidenceRejected("replay receipt already exists")
    raw = input_file.read_bytes()
    verify_bytes(raw)
    # The receipt file is created with O_EXCL. A second validation attempt
    # cannot silently overwrite it. This is a local test replay gate, not
    # a durable or independently witnessed replay ledger.
    fd = os.open(receipt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(
                b"PALACO-BT-CI-RECEIPT-V1|HOLD|DENY|" +
                hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n"
            )
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        # Fail closed: leave even an incomplete receipt blocking replay.
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Deny-only CI incident verifier")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify_once(args.evidence, args.receipt)
    except (EvidenceRejected, OSError, ValueError) as exc:
        print("PALACO CI INCIDENT DENY: " + type(exc).__name__)
        return 1
    print("PALACO CI INCIDENT VERIFIED: structural SHA-256; single-use HOLD/DENY; unsigned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
