"""HOLD-only composition of native pin observations and signed incident policy.

This is a wiring adapter, NOT a TPM/KeyMint implementation. The caller MUST
supply separately trusted native storage identity, a pinned attestation key,
an authenticated issuer registry, a signed policy transport, and trusted clock.
No key is enrolled and no HOLD, transfer, import or deployment is authorized.
"""
from __future__ import annotations

import threading

from native_policy_custody import bind_native_policy_pin_views
from publisher_rotation_gate import RotationPinnedPolicySource
from versioned_incident_policy import VersionedIncidentReviewerGate
from protocol import TransferError


class NativePolicyReviewSession:
    """Expose only evidence-verification and reviewer-inspection decisions."""

    def __init__(self, native_service, protected_identity, pinned_attestation_key,
                 protected_issuers, signed_policy_transport, trusted_clock):
        self._lock = threading.RLock()
        self._held = False
        try:
            custody, policy_pin, issuer_pin = bind_native_policy_pin_views(
                native_service, protected_identity, pinned_attestation_key,
            )
            source = RotationPinnedPolicySource(
                signed_policy_transport, protected_issuers, issuer_pin,
            )
            reviewer = VersionedIncidentReviewerGate(
                source, policy_pin, trusted_clock,
            )
            # Re-attest after wiring all layers to deny observable setup races.
            custody.read_pair()
            self._custody = custody
            self._source = source
            self._reviewer = reviewer
        except Exception as exc:
            raise TransferError("native policy review binding unavailable: HOLD") from exc

    @property
    def is_held(self):
        with self._lock:
            return (self._held or self._custody.is_held or
                    self._source.is_held or self._reviewer.is_held)

    def _decision(self, callback):
        with self._lock:
            if self.is_held:
                return False
            try:
                # Native attestation covers both pins before and after every
                # read-only reviewer action; never assume one prior read lasts.
                self._custody.read_pair()
                allowed = callback()
                self._custody.read_pair()
                if self.is_held:
                    return False
                return allowed is True
            except Exception:
                self._held = True
                return False

    def verify_observation(self, signed, expected_reviewer_nonce):
        """Authenticity check of HOLD evidence, NOT authority to execute."""
        return self._decision(
            lambda: self._reviewer.verify_observation(
                signed, expected_reviewer_nonce,
            )
        )

    def reviewer_can_inspect(self, reviewer_key_id):
        """Only eligibility to inspect; no reviewer action is implemented."""
        return self._decision(
            lambda: self._reviewer.reviewer_can_inspect(reviewer_key_id)
        )
