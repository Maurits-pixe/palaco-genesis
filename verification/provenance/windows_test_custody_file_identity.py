"""WNRA-04X: local, non-authoritative file identity observations.

Filesystem metadata is neither an external custodian nor a cryptographic anchor.
"""
from dataclasses import dataclass
from pathlib import Path

from windows_test_pin_custody_model import CustodyDenied


@dataclass(frozen=True)
class LocalFileIdentity:
    device: int
    inode: int
    size: int
    created_ns: int


def observe_local_identity(path: str) -> LocalFileIdentity:
    if not path:
        raise CustodyDenied("missing custody path")
    try:
        info = Path(path).stat()
    except OSError as exc:
        raise CustodyDenied("custody file identity unavailable") from exc
    if info.st_ino <= 0:
        raise CustodyDenied("filesystem cannot identify custody file")
    return LocalFileIdentity(info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns)


def require_same_local_identity(path: str, expected: LocalFileIdentity) -> None:
    if not isinstance(expected, LocalFileIdentity):
        raise CustodyDenied("missing expected file identity")
    if observe_local_identity(path) != expected:
        raise CustodyDenied("custody file identity changed")
