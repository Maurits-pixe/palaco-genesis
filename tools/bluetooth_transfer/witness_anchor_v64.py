"""PALACO v6.4 external-checkpoint witness for disposable CI, HOLD/DENY.

The trusted Ed25519 PUBLIC key is supplied separately from the database and
checkpoint. The witness signs the current chain snapshot; subsequent edits to
both the ledger and checkpoint cannot be accepted without this witness key.
The test harness uses an ephemeral independent key; it is NOT a real external
authority, durable anchor, trusted timestamp or production attestation.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected
from witness_continuity_v63 import (
    append_incident, append_rotation, public_id, serialize, snapshot,
    strictly_parse, check_hex,
)

PROTOCOL = "PALACO-BT-CI-ANCHOR-V1"
FIELDS = {"protocol", "sequence", "head", "root_id", "witness_id",
          "decision", "authorization", "signature"}


def envelope(state: dict, witness_id: str) -> dict:
    if set(state) != {"sequence", "head", "root_id"}:
        raise EvidenceRejected("invalid chain snapshot")
    if type(state["sequence"]) is not int or state["sequence"] < 1:
        raise EvidenceRejected("invalid chain sequence")
    check_hex(state["head"])
    check_hex(state["root_id"])
    check_hex(witness_id)
    return {
        "protocol": PROTOCOL, "sequence": state["sequence"],
        "head": state["head"], "root_id": state["root_id"],
        "witness_id": witness_id, "decision": "HOLD", "authorization": "DENY",
    }


def sign_checkpoint(state: dict, signer: Ed25519PrivateKey) -> bytes:
    contents = envelope(state, public_id(signer.public_key()))
    contents["signature"] = base64.b64encode(
        signer.sign(serialize(contents))).decode("ascii")
    return serialize(contents)


def verify_checkpoint(raw: bytes, state: dict, trusted_witness: Ed25519PublicKey) -> None:
    checkpoint = strictly_parse(raw, FIELDS)
    canonical = envelope(state, public_id(trusted_witness))
    body = {field: value for field, value in checkpoint.items() if field != "signature"}
    if body != canonical:
        raise EvidenceRejected("checkpoint and trusted root/ledger diverge")
    try:
        signature = checkpoint["signature"]
        if type(signature) is not str:
            raise ValueError("invalid signature type")
        sig = base64.b64decode(signature, validate=True)
        if len(sig) != 64:
            raise ValueError("invalid signature size")
        trusted_witness.verify(sig, serialize(body))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EvidenceRejected("checkpoint witness signature invalid") from exc


def verify_external(ledger: Path, checkpoint: Path,
                    root: Ed25519PublicKey,
                    independently_pinned_witness: Ed25519PublicKey) -> None:
    if not checkpoint.is_file() or checkpoint.is_symlink():
        raise EvidenceRejected("independent checkpoint unavailable")
    verify_checkpoint(checkpoint.read_bytes(), snapshot(ledger, root),
                      independently_pinned_witness)


def write_once(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise EvidenceRejected("unsafe checkpoint path")
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def exercise_ci(evidence: bytes) -> bool:
    import json
    import sqlite3
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        ledger = root / "events.sqlite3"
        checkpoint = root / "anchored-checkpoint.json"
        initial = Ed25519PrivateKey.generate()
        rotated = Ed25519PrivateKey.generate()
        independent = Ed25519PrivateKey.generate()
        root_key = initial.public_key()
        trusted_witness = independent.public_key()

        append_incident(ledger, root_key, initial, evidence)
        append_rotation(ledger, root_key, initial, rotated.public_key())
        second = json.dumps(json.loads(evidence), indent=1).encode("utf-8")
        if second == evidence:
            second += b" "
        append_incident(ledger, root_key, rotated, second)
        original_state = snapshot(ledger, root_key)
        write_once(checkpoint, sign_checkpoint(original_state, independent))
        verify_external(ledger, checkpoint, root_key, trusted_witness)

        # Simulate collusive LOCAL tampering: truncate ledger AND edit the
        # checkpoint to the same old head, but cannot forge the separate
        # independently pinned witness's signature.
        with sqlite3.connect(ledger) as con:
            con.execute("DELETE FROM events WHERE seq=3")
            con.execute("DELETE FROM used_incidents WHERE incident_sha256 NOT IN "
                        "(SELECT json_extract(payload, '$.value') FROM events WHERE kind='incident')")
        rolled_back = snapshot(ledger, root_key)
        # A hostile actor can freely rewrite both the DB and the ordinary
        # unsigned checkpoint, but cannot synthesize the signed receipt.
        forged = envelope(rolled_back, public_id(trusted_witness))
        forged["signature"] = "AA=="
        checkpoint.write_bytes(serialize(forged))
        try:
            verify_external(ledger, checkpoint, root_key, trusted_witness)
        except EvidenceRejected:
            return True
        raise EvidenceRejected("joint ledger/checkpoint tampering accepted")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not exercise_ci(args.ci_evidence.read_bytes()):
            raise EvidenceRejected("witness exercise failed")
    except (EvidenceRejected, OSError, ValueError) as exc:
        print("PALACO v6.4 ANCHOR DENY: " + type(exc).__name__)
        raise SystemExit(1)
    print("PALACO v6.4 ANCHOR PASS (separate ephemeral Ed25519 witness, joint rollback denied; HOLD/DENY)")
