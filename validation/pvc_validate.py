#!/usr/bin/env python3
"""Generate revision-bound G0/G1 evidence for PVC-001."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "validation/core-alpha-scope.json"
GRAPH_PATH = ROOT / "validation/system-graph.json"
GRAPH_SCHEMA_PATH = ROOT / "validation/system-graph.schema.json"
VALIDATOR_VERSION = "0.1.0"
NODE_KINDS = {"service", "capability", "resource", "lifecycle", "event"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, str(error)


def evaluate_g0(
    scope: Any,
    repository: str | None,
    revision: str,
    components: set[str] | None,
    dirty: bool,
) -> dict[str, Any]:
    findings: list[str] = []
    if not isinstance(scope, dict):
        return {"gate": "G0", "result": "FAIL", "findings": ["Scope manifest must be a JSON object."]}

    result = "PASS"
    priority = {"PASS": 0, "INCONCLUSIVE": 1, "HOLD": 2, "FAIL": 3}

    def set_result(candidate: str) -> None:
        nonlocal result
        if priority[candidate] > priority[result]:
            result = candidate

    expected_repository = scope.get("repository")
    if type(scope.get("schema_version")) is not int or scope.get("schema_version") != 1:
        findings.append("Scope manifest schema_version must be 1.")
        set_result("FAIL")
    if not isinstance(scope.get("scope"), str) or not scope["scope"]:
        findings.append("Scope manifest must name the evaluated scope.")
        set_result("HOLD")
    if not isinstance(expected_repository, str) or not expected_repository:
        findings.append("Scope manifest does not declare a repository identity.")
        set_result("HOLD")
    elif repository is None:
        findings.append("Repository identity could not be determined.")
        set_result("HOLD")
    elif repository.casefold() != expected_repository.casefold():
        findings.append(f"Repository mismatch: expected {expected_repository}, found {repository}.")
        set_result("FAIL")

    required = scope.get("required_components")
    excluded = scope.get("excluded_paths")
    if not isinstance(required, list) or not required or not all(
        isinstance(item, str) and item for item in required
    ):
        findings.append("Scope manifest must declare a non-empty required_components list.")
        set_result("HOLD")
    elif len(set(required)) != len(required):
        findings.append("Scope manifest required_components contains duplicate entries.")
        set_result("FAIL")
    elif components is None:
        findings.append("Cargo workspace inventory could not be determined.")
        set_result("HOLD")
    else:
        missing = sorted(set(required) - components)
        undeclared = sorted(components - set(required))
        if missing or undeclared:
            findings.append(
                f"Workspace inventory differs from scope: missing={missing}, undeclared={undeclared}."
            )
            set_result("FAIL")

    if not isinstance(excluded, list) or not all(
        isinstance(item, str) and item for item in excluded
    ):
        findings.append("Scope manifest must declare excluded_paths as a string list.")
        set_result("HOLD")

    if dirty:
        findings.append("Working tree is dirty; the evaluated source is not bound to the commit.")
        set_result("INCONCLUSIVE")
    if not revision:
        findings.append("Source revision could not be determined.")
        set_result("HOLD")

    if not findings:
        findings.append("Repository, revision, and declared Cargo workspace inventory are bound.")
    return {"gate": "G0", "result": result, "findings": findings}


def _is_string_list(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or bool(value))
        and all(isinstance(item, str) and item for item in value)
    )


def evaluate_g1(
    graph: Any,
    scope: Any,
    revision: str,
    graph_error: str | None = None,
) -> dict[str, Any]:
    findings: list[str] = []
    if graph_error == "missing":
        return {"gate": "G1", "result": "HOLD", "findings": ["SystemGraph artifact is not present."]}
    if graph_error is not None:
        return {"gate": "G1", "result": "FAIL", "findings": [f"SystemGraph could not be parsed: {graph_error}"]}
    if not isinstance(scope, dict) or not isinstance(graph, dict):
        return {"gate": "G1", "result": "FAIL", "findings": ["Scope manifest and SystemGraph must be JSON objects."]}

    required_nodes = scope.get("required_graph_nodes")
    required_relations = scope.get("required_graph_relations")
    inventory_ready = (
        _is_string_list(required_nodes, nonempty=True)
        and isinstance(required_relations, list)
        and bool(required_relations)
        and all(
            isinstance(relation, dict)
            and all(
                isinstance(relation.get(key), str) and relation[key]
                for key in ("source", "target", "kind")
            )
            for relation in required_relations
        )
    )

    if type(graph.get("schema_version")) is not int or graph.get("schema_version") != 1:
        findings.append("SystemGraph schema_version must be 1.")
    graph_revision = graph.get("revision")
    if not isinstance(graph_revision, str) or not graph_revision:
        findings.append("SystemGraph must identify its source revision.")

    nodes = graph.get("nodes")
    relation_kinds = graph.get("relation_kinds")
    relations = graph.get("relations")
    if not isinstance(nodes, list):
        findings.append("SystemGraph nodes must be an array.")
        nodes = []
    if not isinstance(relation_kinds, dict) or not relation_kinds:
        findings.append("SystemGraph must declare relation_kinds.")
        relation_kinds = {}
    if not isinstance(relations, list):
        findings.append("SystemGraph relations must be an array.")
        relations = []
    if set(graph) != {"schema_version", "revision", "nodes", "relation_kinds", "relations"}:
        findings.append("SystemGraph must contain only the fields defined by its schema.")

    node_by_id: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            findings.append(f"Node at index {index} must be an object.")
            continue
        node_id = node.get("id")
        node_kind = node.get("kind")
        source_paths = node.get("source_paths")
        if set(node) != {"id", "kind", "source_paths"}:
            findings.append(f"Node at index {index} must contain only id, kind, and source_paths.")
        if not isinstance(node_id, str) or not node_id:
            findings.append(f"Node at index {index} has no valid id.")
            continue
        if node_id in node_by_id:
            findings.append(f"Duplicate node id: {node_id}.")
        if not isinstance(node_kind, str) or node_kind not in NODE_KINDS:
            findings.append(f"Node {node_id} has unsupported kind {node_kind!r}.")
        if not _is_string_list(source_paths, nonempty=True):
            findings.append(f"Node {node_id} must identify at least one source path.")
        else:
            for source_path in source_paths:
                candidate = Path(source_path)
                resolved = (ROOT / candidate).resolve()
                if (
                    candidate.is_absolute()
                    or ".." in candidate.parts
                    or not resolved.is_relative_to(ROOT)
                    or not resolved.exists()
                ):
                    findings.append(f"Node {node_id} references an invalid source path: {source_path}.")
        node_by_id[node_id] = node

    relation_ids: set[tuple[str, str, str]] = set()
    for relation_kind, definition in relation_kinds.items():
        if not isinstance(relation_kind, str) or not relation_kind or not isinstance(definition, dict):
            findings.append("Each relation kind must have a non-empty name and object definition.")
            continue
        if set(definition) != {"meaning", "source_kinds", "target_kinds"}:
            findings.append(f"Relation kind {relation_kind!r} has unexpected or missing fields.")
        if not isinstance(definition.get("meaning"), str) or not definition["meaning"]:
            findings.append(f"Relation kind {relation_kind!r} must declare its meaning.")
        for field in ("source_kinds", "target_kinds"):
            kinds = definition.get(field)
            if not isinstance(kinds, list) or not kinds or any(
                not isinstance(kind, str) or kind not in NODE_KINDS for kind in kinds
            ):
                findings.append(f"Relation kind {relation_kind!r} must declare valid {field}.")

    for index, relation in enumerate(relations):
        if not isinstance(relation, dict):
            findings.append(f"Relation at index {index} must be an object.")
            continue
        source, target, kind = (
            relation.get("source"),
            relation.get("target"),
            relation.get("kind"),
        )
        if set(relation) != {"source", "target", "kind"}:
            findings.append(f"Relation at index {index} must contain only source, target, and kind.")
        if not all(isinstance(item, str) and item for item in (source, target, kind)):
            findings.append(f"Relation at index {index} must identify source, target, and kind.")
            continue
        relation_id = (source, target, kind)
        if relation_id in relation_ids:
            findings.append(f"Duplicate relation: {source} -[{kind}]-> {target}.")
        relation_ids.add(relation_id)
        source_node = node_by_id.get(source)
        target_node = node_by_id.get(target)
        if source_node is None or target_node is None:
            findings.append(f"Relation {source} -[{kind}]-> {target} references an unknown node.")
            continue
        definition = relation_kinds.get(kind)
        if not isinstance(definition, dict):
            findings.append(f"Relation kind {kind!r} is not declared.")
            continue
        if not isinstance(definition.get("meaning"), str) or not definition["meaning"]:
            findings.append(f"Relation kind {kind!r} must declare its meaning.")
        source_kinds = definition.get("source_kinds")
        target_kinds = definition.get("target_kinds")
        if not isinstance(source_kinds, list) or not isinstance(target_kinds, list):
            continue
        if source_node.get("kind") not in source_kinds:
            findings.append(f"Relation {kind!r} does not permit source kind {source_node.get('kind')!r}.")
        if target_node.get("kind") not in target_kinds:
            findings.append(f"Relation {kind!r} does not permit target kind {target_node.get('kind')!r}.")

    if inventory_ready:
        if len(set(required_nodes)) != len(required_nodes):
            findings.append("Scope manifest required_graph_nodes contains duplicate entries.")
        required_relation_ids = [
            (relation["source"], relation["target"], relation["kind"])
            for relation in required_relations
        ]
        if len(set(required_relation_ids)) != len(required_relation_ids):
            findings.append("Scope manifest required_graph_relations contains duplicate entries.")
        for expected in required_nodes:
            if expected not in node_by_id:
                findings.append(f"Required graph node is missing: {expected}.")
        for expected in required_relations:
            relation_id = (expected["source"], expected["target"], expected["kind"])
            if relation_id not in relation_ids:
                findings.append(
                    f"Required graph relation is missing: {expected['source']} -[{expected['kind']}]-> {expected['target']}."
                )

    if findings:
        return {"gate": "G1", "result": "FAIL", "findings": findings}
    if not inventory_ready:
        return {
            "gate": "G1",
            "result": "HOLD",
            "findings": [
                "Approved required_graph_nodes and required_graph_relations inventories are not defined."
            ],
        }
    if graph_revision != revision:
        return {
            "gate": "G1",
            "result": "INCONCLUSIVE",
            "findings": [f"SystemGraph revision {graph_revision} does not match evaluated revision {revision}."],
        }
    return {
        "gate": "G1",
        "result": "PASS",
        "findings": ["SystemGraph structure, declared inventory, relations, and source revision are valid."],
    }


def _git(*args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _repository_identity() -> str | None:
    configured = os.environ.get("GITHUB_REPOSITORY")
    if configured and re.fullmatch(r"[^/]+/[^/]+", configured):
        return configured.removesuffix(".git")
    remote = configured or _git("remote", "get-url", "origin")
    if not remote:
        return None
    match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", remote)
    return match.group(1) if match else None


def _workspace_components() -> set[str] | None:
    completed = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    try:
        metadata = json.loads(completed.stdout)
        return {
            package["name"]
            for package in metadata["packages"]
            if package["id"] in metadata["workspace_members"]
        }
    except (KeyError, TypeError, json.JSONDecodeError):
        return None


def _artifact(path: Path) -> dict[str, str] | None:
    if not path.is_file():
        return None
    try:
        return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)}
    except (OSError, ValueError):
        return {"path": str(path), "sha256": "unavailable"}


def build_report(scope_path: Path, graph_path: Path, output_dir: Path) -> dict[str, Any]:
    scope, scope_error = read_json(scope_path)
    revision = _git("rev-parse", "HEAD") or ""
    dirty = bool(_git("status", "--porcelain"))

    g0 = evaluate_g0(
        scope if scope_error is None else None,
        _repository_identity(),
        revision,
        _workspace_components(),
        dirty,
    )
    if scope_error:
        g0["result"] = "HOLD" if not scope_path.is_file() else "FAIL"
        g0["findings"] = [f"Scope manifest could not be parsed: {scope_error}"]
    graph, graph_error = read_json(graph_path)
    if not graph_path.is_file():
        graph_error = "missing"
    g1 = evaluate_g1(graph, scope if scope_error is None else None, revision, graph_error)

    report: dict[str, Any] = {
        "format_version": 1,
        "validator": {"name": "PVC-001 G0/G1 validator", "version": VALIDATOR_VERSION},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": _repository_identity(),
        "revision": revision or None,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "artifacts": {
            "scope": _artifact(scope_path),
            "system_graph": _artifact(graph_path),
            "system_graph_schema": _artifact(GRAPH_SCHEMA_PATH),
        },
        "gates": [g0, g1],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "pvc-001-evidence.json"
    markdown_path = output_dir / "pvc-001-evidence.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# PVC-001 G0/G1 Evidence",
        "",
        f"- Repository: `{report['repository'] or 'unknown'}`",
        f"- Revision: `{report['revision'] or 'unknown'}`",
        f"- Validator: `{report['validator']['name']} {report['validator']['version']}`",
        f"- Generated: `{report['generated_at']}`",
        "",
        "| Gate | Result | Findings |",
        "|---|---|---|",
    ]
    for gate in report["gates"]:
        findings = "; ".join(gate["findings"]).replace("|", "\\|")
        lines.append(f"| {gate['gate']} | **{gate['result']}** | {findings} |")
    lines.extend(["", "This report records validation evidence only; it grants no authority."])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=SCOPE_PATH)
    parser.add_argument("--graph", type=Path, default=GRAPH_PATH)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(args.scope.resolve(), args.graph.resolve(), args.output_dir.resolve())
    for gate in report["gates"]:
        print(f"{gate['gate']}: {gate['result']}")
        for finding in gate["findings"]:
            print(f"  - {finding}")
    return 1 if any(gate["result"] == "FAIL" for gate in report["gates"]) else 0


if __name__ == "__main__":
    sys.exit(main())
