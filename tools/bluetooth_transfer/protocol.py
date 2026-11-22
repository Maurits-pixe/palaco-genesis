"""PALACO offline Bluetooth payload framing reference (transport independent).

This code does not pair devices, encrypt the radio link or grant authority.
A native BLE adapter and an authenticated identity/consent gate are required.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

MAX_BYTES = 1_048_576
CHUNK_BYTES = 16_384
DOMAIN = b"PALACO:OFFLINE:TRANSFER:V1\0"
ALLOWED_KINDS = frozenset({"citadel", "mundo"})


class TransferError(ValueError):
    """Invalid or untrusted transfer input."""


@dataclass(frozen=True)
class Offer:
    """Untrusted metadata offered by another device."""

    kind: Literal["citadel", "mundo"]
    transfer_id: str
    payload_size: int
    chunk_count: int
    payload_sha256: str


def _sha(payload: bytes) -> str:
    return hashlib.sha256(DOMAIN + payload).hexdigest()


def _validate_id(value: str) -> None:
    if not isinstance(value, str) or len(value) != 32 or any(
        ch not in "0123456789abcdef" for ch in value
    ):
        raise TransferError("transfer_id must be 32 lowercase hex characters")


def _validate_offer(offer: Offer) -> None:
    if offer.kind not in ALLOWED_KINDS:
        raise TransferError("unsupported resource kind")
    _validate_id(offer.transfer_id)
    if type(offer.payload_size) is not int or not 1 <= offer.payload_size <= MAX_BYTES:
        raise TransferError("invalid payload size")
    expected = (offer.payload_size + CHUNK_BYTES - 1) // CHUNK_BYTES
    if type(offer.chunk_count) is not int or offer.chunk_count != expected:
        raise TransferError("invalid chunk count")
    if len(offer.payload_sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in offer.payload_sha256
    ):
        raise TransferError("invalid payload digest")


def make_offer(kind: str, transfer_id: str, payload: bytes) -> Offer:
    """Create bounded transfer metadata; random transfer_id comes from caller."""
    if not isinstance(payload, bytes):
        raise TransferError("payload must be bytes")
    if kind not in ALLOWED_KINDS:
        raise TransferError("unsupported resource kind")
    _validate_id(transfer_id)
    if not 1 <= len(payload) <= MAX_BYTES:
        raise TransferError("payload out of bounds")
    return Offer(kind, transfer_id, len(payload),
                 (len(payload) + CHUNK_BYTES - 1) // CHUNK_BYTES, _sha(payload))


def chunks(payload: bytes) -> tuple[bytes, ...]:
    """Split bounded payload into ordered BLE-adapter-neutral chunks."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_BYTES:
        raise TransferError("payload out of bounds")
    return tuple(payload[i:i + CHUNK_BYTES] for i in range(0, len(payload), CHUNK_BYTES))


class Receiver:
    """One-shot receiver; refuses data without local consent or on replay."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def accept(
        self, offer: Offer, parts: tuple[bytes, ...], *,
        user_approved: bool, identity_verified: bool,
    ) -> bytes:
        """Validate the transfer only; no import, publishing or authorization."""
        _validate_offer(offer)
        if not user_approved or not identity_verified:
            raise TransferError("local consent and external identity verification required")
        if offer.transfer_id in self._seen:
            raise TransferError("replayed transfer")
        if not isinstance(parts, tuple) or len(parts) != offer.chunk_count:
            raise TransferError("missing or extra chunks")
        for index, part in enumerate(parts):
            expected_size = CHUNK_BYTES if index < offer.chunk_count - 1 else (
                offer.payload_size - CHUNK_BYTES * index
            )
            if not isinstance(part, bytes) or len(part) != expected_size:
                raise TransferError("invalid chunk boundary")
        payload = b"".join(parts)
        if len(payload) != offer.payload_size or _sha(payload) != offer.payload_sha256:
            raise TransferError("payload integrity mismatch")
        self._seen.add(offer.transfer_id)
        return payload

    def has_seen(self, transfer_id: str) -> bool:
        """Inspect in-memory replay guard; not durable across restarts."""
        return transfer_id in self._seen


def offer_json(offer: Offer) -> str:
    """Canonical wire metadata. Untrusted until separately authenticated."""
    _validate_offer(offer)
    return json.dumps({
        "chunk_count": offer.chunk_count,
        "kind": offer.kind,
        "payload_sha256": offer.payload_sha256,
        "payload_size": offer.payload_size,
        "protocol": "PALACO-BT-TRANSFER-V1",
        "transfer_id": offer.transfer_id,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_offer(raw: str) -> Offer:
    """Reject unknown/duplicate fields and noncanonical metadata."""
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in pairs:
            if key in parsed:
                raise TransferError("duplicate metadata field")
            parsed[key] = value
        return parsed

    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 2048:
        raise TransferError("metadata out of bounds")
    try:
        data = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (ValueError, TypeError) as exc:
        raise TransferError("invalid metadata JSON") from exc
    required = {"protocol", "kind", "transfer_id", "payload_size",
                "chunk_count", "payload_sha256"}
    if not isinstance(data, dict) or set(data) != required:
        raise TransferError("unexpected metadata fields")
    if data["protocol"] != "PALACO-BT-TRANSFER-V1":
        raise TransferError("unsupported protocol")
    offer = Offer(data["kind"], data["transfer_id"], data["payload_size"],
                  data["chunk_count"], data["payload_sha256"])
    _validate_offer(offer)
    if raw != offer_json(offer):
        raise TransferError("noncanonical offer")
    return offer
