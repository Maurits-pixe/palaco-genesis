"""Offline integrity and structural checks for unsigned PALACO SBOM evidence.

This is not a substitute for third-party SPDX schema validation or signature
verification. It checks artifact consistency and rejects misleading authority.
"""

import argparse
import hashlib
import json
from pathlib import Path


def verify(sbom_bytes, evidence_bytes, expected_commit, metadata_bytes=None):
    document = json.loads(sbom_bytes)
    evidence = json.loads(evidence_bytes)
    if evidence.get("schema") != "palaco-unsigned-sbom-evidence-v0.1":
        raise ValueError("unknown evidence schema")
    if evidence.get("commit") != expected_commit:
        raise ValueError("commit mismatch")
    if evidence.get("sbom_sha256") != hashlib.sha256(sbom_bytes).hexdigest():
        raise ValueError("SBOM digest mismatch")
    if metadata_bytes is not None and evidence.get("metadata_sha256") != hashlib.sha256(metadata_bytes).hexdigest():
        raise ValueError("Cargo metadata digest mismatch")
    if evidence.get("signed") is not False or evidence.get("release_authorized") is not False:
        raise ValueError("unsigned candidate must not claim signing or release authority")
    if document.get("spdxVersion") != "SPDX-2.3" or document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("unexpected SPDX document identity")
    if document.get("name") != "palaco-genesis-cargo-" + expected_commit[:12]:
        raise ValueError("document does not bind to expected commit")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("missing package inventory")
    references = [package["SPDXID"] for package in packages]
    if len(references) != len(set(references)):
        raise ValueError("duplicate package SPDX identifiers")
    valid_references = set(references) | {"SPDXRef-DOCUMENT"}
    for relationship in document.get("relationships", []):
        if relationship["spdxElementId"] not in valid_references or relationship["relatedSpdxElement"] not in valid_references:
            raise ValueError("dangling SPDX relationship")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    verify(
        (args.output_dir / "sbom.spdx.json").read_bytes(),
        (args.output_dir / "evidence.json").read_bytes(),
        args.commit,
        args.metadata.read_bytes(),
    )


if __name__ == "__main__":
    main()
