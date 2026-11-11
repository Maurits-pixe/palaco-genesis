"""WNRA-04C: TEST-ONLY pinned digest check for disposable Windows build-root fixtures.

This checks consumed byte identity against a *caller-supplied* expectation.
It neither authenticates that expectation nor proves file origin, provenance,
lease validity, immutable staging, or production authority.
"""

import hashlib
import hmac
import os
import re

if os.name != "nt":
    raise ImportError("pinned-digest experiment requires native Windows")

from windows_native_relative_test_open import read_fixture_metadata_relative

_DIGEST = re.compile(r"[0-9a-f]{64}\Z", flags=re.ASCII)


def read_fixture_with_pinned_digest(fixture, basename, expected_sha256):
    """Return exact bytes only if they match a test-harness pinned SHA-256.

    Missing, non-canonical and malformed digests fail before filesystem access.
    The separate Windows fixture's root-lifetime and basename gates still apply.
    """
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        raise ValueError("trusted test digest required as 64 lowercase hex digits")
    data = read_fixture_metadata_relative(fixture, basename)
    actual_sha256 = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError("test bytes differ from pinned expected digest")
    return data
