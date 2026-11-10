"""Offline integrity and structural checks for unsigned PALACO SBOM evidence.

This is not a substitute for third-party SPDX schema validation or signature
verification. It checks artifact consistency and rejects misleading authority.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from generate_sbom import canonical, generate, strict_json_loads


def verify(sbom_bytes, evidence_bytes, expected_commit, metadata_bytes):
    document = strict_json_loads(sbom_bytes)
    evidence = strict_json_loads(evidence_bytes)
    if not isinstance(document, dict) or not isinstance(evidence, dict):
        raise ValueError("SBOM and evidence must be JSON objects")
    if not isinstance(expected_commit, str) or len(expected_commit) != 40 or any(
        character not in "0123456789abcdef" for character in expected_commit
    ):
        raise ValueError("expected commit must be a lowercase 40-character Git SHA")
    if evidence.get("schema") != "palaco-unsigned-sbom-evidence-v0.1":
        raise ValueError("unknown evidence schema")
    if evidence.get("commit") != expected_commit:
        raise ValueError("commit mismatch")
    if evidence.get("sbom_sha256") != hashlib.sha256(sbom_bytes).hexdigest():
        raise ValueError("SBOM digest mismatch")
    if evidence.get("metadata_sha256") != hashlib.sha256(metadata_bytes).hexdigest():
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
    if any(not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str) for package in packages):
        raise ValueError("malformed SPDX package record")
    references = [package["SPDXID"] for package in packages]
    if len(references) != len(set(references)):
        raise ValueError("duplicate package SPDX identifiers")
    valid_references = set(references) | {"SPDXRef-DOCUMENT"}
    relationships = document.get("relationships")
    if not isinstance(relationships, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("spdxElementId"), str)
        or not isinstance(item.get("relatedSpdxElement"), str)
        or item.get("relationshipType") not in ("DESCRIBES", "DEPENDS_ON")
        for item in relationships
    ):
        raise ValueError("malformed SPDX relationships")
    for relationship in relationships:
        if relationship["spdxElementId"] not in valid_references or relationship["relatedSpdxElement"] not in valid_references:
            raise ValueError("dangling SPDX relationship")
    try:
        created = document["creationInfo"]["created"]
        parsed = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        reconstructed = generate(strict_json_loads(metadata_bytes), expected_commit, int(parsed.timestamp()))
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("invalid source metadata or SPDX creation timestamp") from error
    if canonical(reconstructed) != canonical(document):
        raise ValueError("SBOM does not match Cargo metadata reconstruction")
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

