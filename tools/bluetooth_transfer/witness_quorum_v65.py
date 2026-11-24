"""PALACO Bluetooth v6.5: pinned 2-of-3 checkpoint witness quorum (CI only).

Three independent in-memory Ed25519 identities are pinned by the caller.
Two distinct matching receipts are required. ANY valid signed divergent
receipt fails closed even when two agreeing receipts exist. An invalid or
unknown signed receipt is not silently ignored. Missing one receipt is
tolerated, missing two is not. No network, HSM, persistent custody or
real independent organizations are involved; fixed HOLD / DENY only.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from verify_scm_ci_incident import EvidenceRejected
from witness_anchor_v64 import FIELDS, sign_checkpoint, verify_checkpoint, write_once
from witness_continuity_v63 import (
    append_incident, append_rotation, public_id, serialize, snapshot, strictly_parse
)

ROSTER_SIZE = 3
THRESHOLD = 2


def verify_quorum(ledger: Path, root: Ed25519PublicKey,
                  pinned_witnesses: dict[str, Ed25519PublicKey],
                  receipts: list[Path]) -> None:
    if len(pinned_witnesses) != ROSTER_SIZE:
        raise EvidenceRejected("require exactly three pinned witnesses")
    if len(set(pinned_witnesses)) != ROSTER_SIZE:
        raise EvidenceRejected("duplicate trusted identity")
    for witness_id, key in pinned_witnesses.items():
        if public_id(key) != witness_id:
            raise EvidenceRejected("pinned witness identity mismatch")
    if len(set(receipts)) != len(receipts):
        raise EvidenceRejected("duplicate receipt path")
    state = snapshot(ledger, root)
    seen: set[str] = set()
    for path in receipts:
        if path.is_symlink() or not path.is_file():
            raise EvidenceRejected("receipt missing or unsafe")
        doc = strictly_parse(path.read_bytes(), FIELDS)
        witness_id = doc["witness_id"]
        if type(witness_id) is not str or witness_id not in pinned_witnesses:
            raise EvidenceRejected("unknown witness identity")
        if witness_id in seen:
            raise EvidenceRejected("duplicate witness endorsement")
        seen.add(witness_id)
        # Fail-closed even if the quorum would remain 2-of-3: a valid
        # contrary signature means an actual split-view must be investigated.
        verify_checkpoint(path.read_bytes(), state, pinned_witnesses[witness_id])
    if len(seen) < THRESHOLD:
        raise EvidenceRejected("insufficient distinct signed witnesses")


def exercise_ci(evidence: bytes) -> bool:
    import json
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        ledger = root / "ledger.sqlite3"
        root_signer = Ed25519PrivateKey.generate()
        rotated = Ed25519PrivateKey.generate()
        root_public = root_signer.public_key()
        append_incident(ledger, root_public, root_signer, evidence)
        append_rotation(ledger, root_public, root_signer, rotated.public_key())
        second = json.dumps(json.loads(evidence), indent=1).encode("utf-8")
        if second == evidence:
            second += b" "
        append_incident(ledger, root_public, rotated, second)
        state = snapshot(ledger, root_public)
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pinned = {public_id(key.public_key()): key.public_key() for key in keys}
        paths = [root / f"receipt-{i}.json" for i in range(3)]
        for path, key in zip(paths, keys):
            write_once(path, sign_checkpoint(state, key))
        verify_quorum(ledger, root_public, pinned, paths)
        verify_quorum(ledger, root_public, pinned, paths[:2])
        try:
            verify_quorum(ledger, root_public, pinned, paths[:1])
        except EvidenceRejected:
            pass
        else:
            raise EvidenceRejected("single witness accepted")
        # A validly signed but contradictory checkpoint cannot be hidden
        # behind a numerically sufficient honest 2-of-3 quorum.
        contradictory = dict(state)
        contradictory["head"] = "f" * 64
        paths[2].write_bytes(sign_checkpoint(contradictory, keys[2]))
        try:
            verify_quorum(ledger, root_public, pinned, paths)
        except EvidenceRejected:
            pass
        else:
            raise EvidenceRejected("split-view quorum accepted")
        return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not exercise_ci(args.ci_evidence.read_bytes()):
            raise EvidenceRejected("quorum smoke failed")
    except (EvidenceRejected, OSError, ValueError) as ex:
        print("PALACO v6.5 QUORUM DENY: " + type(ex).__name__)
        raise SystemExit(1)
    print("PALACO v6.5 QUORUM PASS (ephemeral 2-of-3, split-view denied; HOLD/DENY)")
