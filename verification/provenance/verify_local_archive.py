"""Exercise the real generated SBOM files through the offline ZIP verifier.

This pre-upload check does not verify the GitHub-hosted ZIP digest, which must
be obtained independently from the trusted Actions artifact listing.
"""

import argparse
import hashlib
import io
import zipfile
from pathlib import Path

from verify_artifact import verify_artifact


NAMES = ("cargo-metadata.json", "evidence.json", "sbom.spdx.json")


def verify_local_archive(directory, commit):
    files = {name: (directory / name).read_bytes() for name in NAMES}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in NAMES:
            archive.writestr(name, files[name])
    data = output.getvalue()
    return verify_artifact(data, hashlib.sha256(data).hexdigest(), commit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    verify_local_archive(args.output_dir, args.commit)
    print("Pre-upload ZIP round-trip: PASS (unsigned; local digest only)")


if __name__ == "__main__":
    main()
