"""Bounded canonical request framing for a FUTURE privileged Windows service.

This is pure parsing. It opens no named pipes, authenticates no callers, and
provides no anti-replay or OS trust. A privileged service MUST independently
authenticate the IPC peer, authorize its operation, provision its own nonce and
enforce freshness/replay rules before processing any request.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from protocol import TransferError

PROTOCOL = "PALACO-BT-WIN-IPC-V1"
MAX_FRAME = 1024
_ALLOWED = frozenset(("protocol", "operation", "namespace", "device_binding",
                      "generation", "challenge"))
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


@dataclass(frozen=True)
class WindowsInspectRequest:
    namespace: bytes
    device_binding: bytes
    generation: int
    challenge: bytes

    def __post_init__(self):
        if (type(self.namespace) is not bytes or len(self.namespace) != 32
                or type(self.device_binding) is not bytes or len(self.device_binding) != 32
                or type(self.challenge) is not bytes or len(self.challenge) != 32
                or type(self.generation) is not int
                or not 1 <= self.generation < 2**63):
            raise TransferError("malformed Windows IPC inspection request: HOLD")


def encode_windows_inspect_request(request: WindowsInspectRequest) -> bytes:
    if type(request) is not WindowsInspectRequest:
        raise TransferError("invalid IPC request: HOLD")
    document = {
        "protocol": PROTOCOL,
        "operation": "inspect",
        "namespace": request.namespace.hex(),
        "device_binding": request.device_binding.hex(),
        "generation": request.generation,
        "challenge": request.challenge.hex(),
    }
    wire = json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")
    if len(wire) > MAX_FRAME:
        raise TransferError("Windows IPC frame exceeds limit: HOLD")
    return wire


def _reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise TransferError("duplicate IPC key: HOLD")
        document[key] = value
    return document


def decode_windows_inspect_request(frame: bytes) -> WindowsInspectRequest:
    """Fail-closed framing parser; never treats a parsed request as authorized."""
    if type(frame) is not bytes or not 0 < len(frame) <= MAX_FRAME:
        raise TransferError("invalid IPC frame size: HOLD")
    try:
        text = frame.decode("ascii")
        document = json.loads(text, object_pairs_hook=_reject_duplicates,
                              parse_constant=lambda _: (_ for _ in ()).throw(
                                  ValueError("nonfinite value")))
        if type(document) is not dict or set(document) != _ALLOWED:
            raise ValueError("unrecognized/missing IPC fields")
        if document["protocol"] != PROTOCOL or document["operation"] != "inspect":
            raise ValueError("unsupported IPC request")
        if any(type(document[k]) is not str or not _HEX64.fullmatch(document[k])
               for k in ("namespace", "device_binding", "challenge")):
            raise ValueError("invalid canonical IPC identifier")
        request = WindowsInspectRequest(
            bytes.fromhex(document["namespace"]),
            bytes.fromhex(document["device_binding"]),
            document["generation"],
            bytes.fromhex(document["challenge"]),
        )
        if encode_windows_inspect_request(request) != frame:
            raise ValueError("noncanonical IPC frame")
        return request
    except (ValueError, UnicodeError, TypeError, KeyError, OverflowError) as exc:
        raise TransferError("invalid Windows IPC request: HOLD") from exc
