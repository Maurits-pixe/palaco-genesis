"""Trust-anchor snapshot gate for the root-signed PALACO reviewer policy.

The external native anchor MUST guarantee integrity and anti-rollback of the
root public key and policy revision. Here we only check its interface and
re-read the anchor before every review verification; this module does NOT
create, provision or secure that anchor.

Changes or unavailability DENY. A valid review still means HOLD only.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import Callable, Protocol

from protocol import TransferError
from signed_reviewer_policy import SignedReviewerPolicy, load_signed_policy


@dataclass(frozen=True)
class PinnedPolicyState:
    root_public_key: bytes
    revision: int

    def __post_init__(self) -> None:
        if (type(self.root_public_key) is not bytes or
                len(self.root_public_key) != 32 or
                type(self.revision) is not int or
                not 1 <= self.revision < 2**63):
            raise TransferError("invalid protected root/revision state")


class ProtectedPolicyAnchor(Protocol):
    """Native-only trusted source of root key and anti-rollback revision."""

    def read(self) -> PinnedPolicyState:
        """Read atomic authoritative root and revision snapshot."""


class AnchoredReviewVerifier:
    """Recheck anchor on each signature verification; fail closed on changes."""

    def __init__(
        self, policy: SignedReviewerPolicy, anchor: ProtectedPolicyAnchor,
        trusted_clock: Callable[[], int],
    ) -> None:
        if not callable(getattr(anchor, "read", None)):
            raise TransferError("protected policy anchor required")
        self._anchor = anchor
        self._snapshot = self._read_anchor()
        self._delegate = load_signed_policy(
            policy, self._snapshot.root_public_key,
            self._snapshot.revision, trusted_clock,
        )

    def _read_anchor(self) -> PinnedPolicyState:
        try:
            state = self._anchor.read()
        except Exception as exc:
            raise TransferError("protected policy anchor unavailable") from exc
        if type(state) is not PinnedPolicyState:
            raise TransferError("invalid protected policy anchor")
        return state

    def verify(self, reviewer_key_id: str, message: bytes, signature: bytes) -> bool:
        """Reject stale policy after root rotation, revision change, or anchor loss."""
        try:
            current = self._read_anchor()
        except TransferError:
            return False
        if (current.revision != self._snapshot.revision or
                not hmac.compare_digest(
                    current.root_public_key, self._snapshot.root_public_key,
                )):
            return False
        signature_valid = self._delegate.verify(reviewer_key_id, message, signature)
        if not signature_valid:
            return False
        # Check again after signature verification to catch policy rotation
        # while the verifier was running. This is NOT a native atomic lease.
        try:
            final = self._read_anchor()
        except TransferError:
            return False
        return (final.revision == self._snapshot.revision and
                hmac.compare_digest(
                    final.root_public_key, self._snapshot.root_public_key,
                ))
