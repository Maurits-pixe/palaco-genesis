"""Generate deterministic SPDX 2.3 package inventory and unsigned evidence manifest."""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def strict_json_loads(data):
    """Reject ambiguous JSON keys at every nesting level."""
    def reject_constant(value):
        raise ValueError("non-finite JSON value: " + value)

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def license_expression(value):
    if not value:
        return "NOASSERTION"
    # Historic Cargo manifests allow `MIT/Apache-2.0` for a license choice;
    # SPDX 2.3 requires an explicit operator. Do not reinterpret other syntax.
    if "/" in value and re.fullmatch(r"[A-Za-z0-9.+-]+(?:/[A-Za-z0-9.+-]+)+", value):
        return value.replace("/", " OR ")
    return value


def generate(metadata, commit, epoch):
    if not isinstance(metadata, dict):
        raise ValueError("cargo metadata must be an object")
    if "format_version" in metadata and metadata["format_version"] != 1:
        raise ValueError("unsupported cargo metadata format_version")
    if not isinstance(commit, str) or len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError("commit must be a 40-character lowercase Git SHA")
    if type(epoch) is not int or epoch < 0:
        raise ValueError("source epoch must be a nonnegative integer")
    packages = metadata.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("cargo metadata must include packages")
    if any(
        not isinstance(package, dict)
        or any(not isinstance(package.get(key), str) or not package[key] for key in ("id", "name", "version"))
        or (package.get("license") is not None and not isinstance(package["license"], str))
        for package in packages
    ):
        raise ValueError("malformed cargo package record")
    ids = [package["id"] for package in packages]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate package IDs")
    references = {identifier: "SPDXRef-Package-" + hashlib.sha256(identifier.encode()).hexdigest()[:24] for identifier in ids}
    entries = []
    for package in sorted(packages, key=lambda item: item["id"]):
        entries.append({
            "SPDXID": references[package["id"]],
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_expression(package.get("license")),
            "copyrightText": "NOASSERTION",
        })
    # Cargo metadata must be internally complete. Missing links would make
    # the generated evidence look valid while omitting real dependencies.
    workspace_members = metadata.get("workspace_members")
    if not isinstance(workspace_members, list) or any(not isinstance(item, str) for item in workspace_members):
        raise ValueError("malformed workspace members")
    if len(workspace_members) != len(set(workspace_members)):
        raise ValueError("duplicate workspace members")
    unknown_members = set(workspace_members) - references.keys()
    if unknown_members:
        raise ValueError("unknown workspace member IDs: " + ", ".join(sorted(unknown_members)))
    relations = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": references[item], "relationshipType": "DESCRIBES"}
                 for item in sorted(workspace_members)]
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError("cargo metadata must include a resolve graph")
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("cargo metadata resolve graph must include nodes")
    node_ids = [node.get("id") for node in nodes if isinstance(node, dict)]
    if len(node_ids) != len(nodes) or any(not isinstance(identifier, str) for identifier in node_ids):
        raise ValueError("malformed resolve node")
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate resolve node IDs")
    root = resolve.get("root")
    if root is not None and (not isinstance(root, str) or root not in references or root not in workspace_members):
        raise ValueError("invalid resolve root")
    missing_nodes = references.keys() - set(node_ids)
    if missing_nodes:
        raise ValueError("packages missing from resolve graph: " + ", ".join(sorted(missing_nodes)))
    for node in nodes:
        node_id = node["id"]
        if node_id not in references:
            raise ValueError("unknown resolve node ID: " + node_id)
        dependencies = node.get("dependencies")
        if not isinstance(dependencies, list) or any(not isinstance(dep, str) for dep in dependencies):
            raise ValueError("malformed dependencies for resolve node: " + node_id)
        if len(dependencies) != len(set(dependencies)):
            raise ValueError("duplicate dependencies for resolve node: " + node_id)
        # Cargo metadata exposes both flattened package IDs and detailed
        # dependency records. Compare them when detailed records are present;
        # otherwise a forged flattened list could silently alter the SBOM.
        if metadata.get("format_version") == 1 and "deps" not in node:
            raise ValueError("missing detailed dependencies for Cargo format 1 resolve node: " + node_id)
        if "deps" in node:
            details = node["deps"]
            if not isinstance(details, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("pkg"), str)
                or not isinstance(item.get("name"), str) or not item["name"]
                or not isinstance(item.get("dep_kinds"), list)
                for item in details
            ):
                raise ValueError("malformed detailed dependencies for resolve node: " + node_id)
            if set(dependencies) != {item["pkg"] for item in details}:
                raise ValueError("dependency records disagree for resolve node: " + node_id)
        for dependency in dependencies:
            if dependency not in references:
                raise ValueError("unknown dependency ID: " + dependency + " from " + node_id)
            relations.append({"spdxElementId": references[node_id], "relatedSpdxElement": references[dependency], "relationshipType": "DEPENDS_ON"})
    relations.sort(key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"]))
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "palaco-genesis-cargo-" + commit[:12],
        "documentNamespace": "https://github.com/Maurits-pixe/palaco-genesis/spdx/" + commit,
        "creationInfo": {"creators": ["Tool: palaco-spdx-generator-0.1"], "created": datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "packages": entries,
        "relationships": relations,
    }
    return sbom


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-epoch", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    metadata_bytes = args.metadata.read_bytes()
    document = generate(strict_json_loads(metadata_bytes), args.commit, args.source_epoch)
    output = canonical(document)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "sbom.spdx.json").write_bytes(output)
    evidence = {
        "schema": "palaco-unsigned-sbom-evidence-v0.1",
        "commit": args.commit,
        "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        "sbom_sha256": hashlib.sha256(output).hexdigest(),
        "signed": False,
        "release_authorized": False,
    }
    (args.output_dir / "evidence.json").write_bytes(canonical(evidence))


if __name__ == "__main__":
    main()

