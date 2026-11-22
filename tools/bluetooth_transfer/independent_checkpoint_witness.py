"""Second independently protected witness for native challenge checkpoints.

The native signed checkpoint alone does not prevent a compromised signer from
attesting rollback. This fail-closed wrapper requires a separate authoritative
monotonic witness, outside the native service's rollback domain.

Witness writes occur FIRST. Native and witness stores are NOT atomic; any
failure after witness advancement causes HOLD and requires offline supervised
reconciliation. No repair or rollback operation is supplied here.

IMPORTANT: This is an integration contract. Only a genuinely independent,
durable anti-rollback service can make the witness trustworthy. An in-memory
fake, SQLite table, ordinary encrypted file, or same-device signer cannot.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Protocol

from anchored_challenges import _validate_state
from protocol import TransferError


@dataclass(frozen=True)
class WitnessCheckpoint:
    """Namespace-scoped, monotonic revision and content commitment."""

    namespace: bytes
    revision: int
    count: int
    root: str

    def __post_init__(self):
        if type(self.namespace) is not bytes or len(self.namespace) != 32:
            raise TransferError("invalid witness namespace")
        if type(self.revision) is not int or not 0 <= self.revision < 2**63:
            raise TransferError("invalid witness revision")
        _validate_state((self.count, self.root))


class ProtectedCheckpointWitness(Protocol):
    """Independent protected compare-and-increment service (NOT implemented)."""

    def read(self) -> WitnessCheckpoint: ...

    def advance(
        self, previous: tuple[int, str], current: tuple[int, str],
    ) -> None:
        self._require_live()
        try:
            before = _validate_state(previous)
            after = _validate_state(current)
            if (after == before or after[0] not in (before[0], before[0] + 1)):
                raise TransferError("invalid witnessed checkpoint transition")
            if self.read() != before:
                raise TransferError("stale witnessed checkpoint: HOLD")
            witness_before = self._witness_snapshot()
            if (witness_before.count != before[0] or
                    not hmac.compare_digest(witness_before.root, before[1]) or
                    witness_before.revision == 2**63 - 1):
                raise TransferError("witness CAS mismatch or exhausted: HOLD")
            witness_after = WitnessCheckpoint(
                self._namespace, witness_before.revision + 1, after[0], after[1],
            )
            try:
                self._witness.advance(witness_before, witness_after)
            except Exception as exc:
                raise TransferError("witness advancement uncertain: HOLD") from exc
            # Witness advances first. A failure below MUST leave system in HOLD;
            # never roll back the witness just to restore availability.
            try:
                self._native.advance(before, after)
            except Exception as exc:
                raise TransferError("native advance after witness write failed: HOLD") from exc
            if self.read() != after:
                raise TransferError("post-write witness checkpoint disagreement: HOLD")
        except TransferError:
            self._held = True
            raise
