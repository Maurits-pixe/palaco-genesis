"""Read-only verification of a downloaded GitHub unsigned SBOM ZIP artifact.

Archive digest must come from the trusted workflow artifact listing, not from
the ZIP itself. Verification establishes consistency, not signature authority.
"""

import argparse
import hashlib
import io
import re
import zipfile
from pathlib import Path

from verify_evidence import verify


EXPECTED = {"sbom.spdx.json", "evidence.json", "cargo-metadata.json"}
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def verify_artifact(archive_bytes, expected_archive_sha256, expected_commit):
    if not isinstance(expected_archive_sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_archive_sha256) is None:
        raise ValueError("expected archive SHA-256 required")
    if not isinstance(archive_bytes, bytes) or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("invalid or oversized archive")
    if hashlib.sha256(archive_bytes).hexdigest() != expected_archive_sha256.lower():
        raise ValueError("archive SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(EXPECTED) or set(names) != EXPECTED:
            raise ValueError("unexpected or duplicate artifact entries")
        if any(entry.is_dir() or entry.file_size > MAX_FILE_BYTES or entry.flag_bits & 1 for entry in entries):
            raise ValueError("unexpected directory or oversized artifact entry")
        contents = {}
        for name in EXPECTED:
            with archive.open(name) as member:
                contents[name] = member.read(MAX_FILE_BYTES + 1)
            if len(contents[name]) > MAX_FILE_BYTES:
                raise ValueError("decompressed artifact entry too large")
    return verify(
        contents["sbom.spdx.json"],
        contents["evidence.json"],
        expected_commit,
        contents["cargo-metadata.json"],
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    verify_artifact(args.artifact.read_bytes(), args.archive_sha256, args.commit)
    print("Unsigned SBOM artifact: integrity and reconstruction checks PASS (not an attestation)")


if __name__ == "__main__":
    main()

