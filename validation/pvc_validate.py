#!/usr/bin/env python3
"""Generate revision-bound G0-G9 evidence for PVC-001."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "validation/core-alpha-scope.json"
GRAPH_PATH = ROOT / "validation/system-graph.json"
GRAPH_SCHEMA_PATH = ROOT / "validation/system-graph.schema.json"
ORDERING_PATH = ROOT / "validation/dependency-ordering.json"
PLAN_PATH = ROOT / "validation/execution-plan.json"
PLAN_SCHEMA_PATH = ROOT / "validation/execution-plan.schema.json"
VALIDATOR_VERSION = "0.10.0"
G6_RULESET_VERSION = "1.0.0"
G8_CHECKLIST_PATH = ROOT / "validation/security_checklist.md"
G8_THREAT_MODEL_PATH = ROOT / "release-registry/THREAT-MODEL.md"
G9_RELEASE_PATH = ROOT / "validation/release_validation.md"
GATE_RESULTS = {"PASS", "FAIL", "HOLD", "INCONCLUSIVE"}
G8_REQUIRED_CONTROLS = {
    "SEC-THREAT-MODEL",
    "SEC-SUPPLY-CHAIN",
    "SEC-SECRETS-CONFIG",
    "SEC-ADVERSARIAL",
    "SEC-INDEPENDENT-REVIEW",
}
NODE_KINDS = {"service", "capability", "resource", "lifecycle", "event"}
G4_SCENARIOS = {
    "runtime_plan_confirms_execution_path",
    "runtime_plan_escalates_non_executable_scope",
    "runtime_plan_safe_state_fails_closed",
    "kernel_cycle_confirms_execution_path",
    "kernel_cycle_escalates_non_executable_scope",
    "kernel_cycle_safe_state_fails_closed",
}
G5_SCENARIOS = {
    "event_bus_publishes_events_without_authority_operations",
    "append_and_replay_reconstructs_the_complete_lifecycle",
    "revocation_survives_snapshot_replay",
    "missing_event_provenance_is_rejected_before_commit",
    "observatory_snapshot_marks_current_execution_as_current",
    "observatory_snapshot_marks_observe_scope_as_degraded",
    "observatory_snapshot_marks_missing_sensor_coverage_as_safe_state",
    "observatory_snapshot_preserves_runtime_expiry_after_observation",
    "observatory_snapshot_does_not_change_runtime_authority_state",
    "action_flow_requires_authorization",
}
G7_SCENARIOS = G4_SCENARIOS | G5_SCENARIOS


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


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
    approval = scope.get("graph_inventory_approval")
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
    approval_ready = (
        isinstance(approval, dict)
        and approval.get("status") == "approved"
        and isinstance(approval.get("graph_revision"), str)
        and bool(approval["graph_revision"])
        and isinstance(approval.get("approved_by"), str)
        and bool(approval["approved_by"])
        and isinstance(approval.get("decision_ref"), str)
        and bool(approval["decision_ref"])
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
    if not approval_ready:
        return {
            "gate": "G1",
            "result": "HOLD",
            "findings": [
                "SystemGraph inventory lacks a recorded approval, approver, or decision reference."
            ],
        }
    if graph_revision != approval["graph_revision"]:
        return {
            "gate": "G1",
            "result": "INCONCLUSIVE",
            "findings": [
                f"SystemGraph revision {graph_revision} does not match approved graph revision "
                f"{approval['graph_revision']}."
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
        "findings": [
            "SystemGraph structure, approved inventory, relations, and source revision are valid."
        ],
    }


def _topological_order(
    nodes: list[str], edges: list[tuple[str, str]]
) -> tuple[list[str] | None, list[str] | None]:
    dependencies = {node: set() for node in nodes}
    dependents = {node: set() for node in nodes}
    for source, target in edges:
        if source not in dependencies or target not in dependencies:
            return None, [f"Dependency edge references an unknown node: {source} -> {target}."]
        if source == target:
            return None, [f"Self-dependency is prohibited: {source} -> {target}."]
        dependencies[source].add(target)
        dependents[target].add(source)

    ready = sorted(node for node, deps in dependencies.items() if not deps)
    order: list[str] = []
    while ready:
        node = ready.pop(0)
        order.append(node)
        for dependent in sorted(dependents[node]):
            dependencies[dependent].discard(node)
            if not dependencies[dependent] and dependent not in order and dependent not in ready:
                ready.append(dependent)
        ready.sort()

    remaining = sorted(node for node, deps in dependencies.items() if deps)
    if remaining:
        return None, [f"Dependency cycle detected among: {', '.join(remaining)}."]
    return order, None


def _dependency_graph_digest(graph: dict[str, Any]) -> str:
    canonical = json.dumps(graph, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _ordering_approval_digest(
    graph_sha256: str,
    startup_constraints: list[Any],
    shutdown_constraints: list[Any],
    approved_by: str,
    decision_ref: str,
) -> str:
    payload = {
        "graph_sha256": graph_sha256,
        "startup_constraints": startup_constraints,
        "shutdown_constraints": shutdown_constraints,
        "approved_by": approved_by,
        "decision_ref": decision_ref,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def evaluate_g2(
    nodes: Any,
    edges: Any,
    ordering: Any,
    ordering_error: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    findings: list[str] = []
    graph: dict[str, Any] = {
        "dependency_scope": "workspace-local dependencies across normal, build, and dev kinds",
        "nodes": [],
        "edges": [],
    }

    if not isinstance(nodes, list) or not nodes or any(
        not isinstance(node, str) or not node for node in nodes
    ):
        return (
            {"gate": "G2", "result": "HOLD", "findings": ["Cargo workspace dependency inventory is unavailable."]},
            graph,
        )
    if len(set(nodes)) != len(nodes):
        return (
            {"gate": "G2", "result": "FAIL", "findings": ["Cargo workspace dependency inventory contains duplicate package names."]},
            graph,
        )
    graph["nodes"] = sorted(nodes)

    if not isinstance(edges, list):
        return (
            {"gate": "G2", "result": "HOLD", "findings": ["Cargo workspace dependency edges are unavailable."]},
            graph,
        )
    normalized_edges: list[tuple[str, str]] = []
    for edge in edges:
        if (
            not isinstance(edge, (list, tuple))
            or len(edge) != 2
            or not all(isinstance(item, str) and item for item in edge)
        ):
            findings.append(f"Invalid Cargo dependency edge: {edge!r}.")
            continue
        normalized_edges.append((edge[0], edge[1]))
    graph["edges"] = [
        {"package": source, "depends_on": target}
        for source, target in sorted(set(normalized_edges))
    ]
    if len(set(normalized_edges)) != len(normalized_edges):
        findings.append("Cargo dependency graph contains duplicate edges.")
    order, cycle_error = _topological_order(nodes, normalized_edges)
    if cycle_error:
        findings.extend(cycle_error)
    else:
        graph["topological_order"] = order
    graph_digest = _dependency_graph_digest(graph)
    graph["sha256"] = graph_digest

    if findings:
        return {"gate": "G2", "result": "FAIL", "findings": findings}, graph

    if ordering_error == "missing":
        return (
            {"gate": "G2", "result": "HOLD", "findings": ["Startup/shutdown ordering evidence is not present."]},
            graph,
        )
    if ordering_error:
        return (
            {"gate": "G2", "result": "FAIL", "findings": [f"Dependency ordering input is invalid: {ordering_error}"]},
            graph,
        )
    if not isinstance(ordering, dict):
        return (
            {"gate": "G2", "result": "HOLD", "findings": ["Startup/shutdown ordering constraints are not defined."]},
            graph,
        )
    if type(ordering.get("schema_version")) is not int or ordering["schema_version"] != 1:
        return (
            {"gate": "G2", "result": "FAIL", "findings": ["Dependency ordering schema_version must be 1."]},
            graph,
        )
    expected_ordering_fields = {
        "schema_version",
        "status",
        "graph_sha256",
        "approval_sha256",
        "startup_constraints",
        "shutdown_constraints",
        "approved_by",
        "decision_ref",
    }
    if set(ordering) != expected_ordering_fields:
        return (
            {"gate": "G2", "result": "FAIL", "findings": ["Dependency ordering input has unexpected or missing fields."]},
            graph,
        )

    ordering_constraints: dict[str, list[tuple[str, str]]] = {}
    for field in ("startup_constraints", "shutdown_constraints"):
        value = ordering.get(field)
        if not isinstance(value, list):
            return (
                {"gate": "G2", "result": "HOLD", "findings": [f"{field} are not explicitly defined."]},
                graph,
            )
        parsed: list[tuple[str, str]] = []
        for item in value:
            if (
                not isinstance(item, dict)
                or set(item) != {"before", "after"}
                or not all(isinstance(item.get(key), str) and item[key] for key in ("before", "after"))
            ):
                findings.append(f"{field} contains an invalid ordering constraint: {item!r}.")
                continue
            parsed.append((item["after"], item["before"]))
        ordering_constraints[field] = parsed
        dependency_edges = (
            normalized_edges
            if field == "startup_constraints"
            else [(dependency, package) for package, dependency in normalized_edges]
        )
        _, constraint_error = _topological_order(nodes, dependency_edges + parsed)
        if constraint_error:
            findings.extend(f"{field} conflicts with dependency ordering: {error}" for error in constraint_error)
    if findings:
        return {"gate": "G2", "result": "FAIL", "findings": findings}, graph

    approval = {
        "status": ordering.get("status"),
        "graph_sha256": ordering.get("graph_sha256"),
        "approval_sha256": ordering.get("approval_sha256"),
        "approved_by": ordering.get("approved_by"),
        "decision_ref": ordering.get("decision_ref"),
    }
    expected_approval_digest = _ordering_approval_digest(
        graph_digest,
        ordering["startup_constraints"],
        ordering["shutdown_constraints"],
        approval["approved_by"] if isinstance(approval["approved_by"], str) else "",
        approval["decision_ref"] if isinstance(approval["decision_ref"], str) else "",
    )
    if (
        approval["status"] != "approved"
        or approval["graph_sha256"] != graph_digest
        or approval["approval_sha256"] != expected_approval_digest
        or not isinstance(approval["approved_by"], str)
        or not approval["approved_by"]
        or not isinstance(approval["decision_ref"], str)
        or not approval["decision_ref"]
    ):
        return (
            {
                "gate": "G2",
                "result": "HOLD",
                "findings": [
                    "Cargo dependency graph is acyclic, but startup/shutdown constraints lack "
                    "an approval bound to the current graph digest."
                ],
            },
            graph,
        )
    return (
        {
            "gate": "G2",
            "result": "PASS",
            "findings": [
                f"Cargo dependency graph is acyclic and approved startup/shutdown constraints are valid ({graph_digest})."
            ],
        },
        graph,
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def evaluate_g3(
    graph: Any,
    plan: Any,
    revision: str,
    g1_result: str,
    g2_result: str,
    plan_error: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    empty_schedule: dict[str, Any] = {"execution_layers": [], "plan_sha256": None}
    if plan_error == "missing":
        return (
            {"gate": "G3", "result": "HOLD", "findings": ["ExecutionPlan artifact is not present."]},
            empty_schedule,
        )
    if plan_error is not None:
        return (
            {"gate": "G3", "result": "FAIL", "findings": [f"ExecutionPlan could not be parsed: {plan_error}"]},
            empty_schedule,
        )
    if not isinstance(plan, dict):
        return (
            {"gate": "G3", "result": "FAIL", "findings": ["ExecutionPlan must be a JSON object."]},
            empty_schedule,
        )

    required_fields = {
        "schema_version",
        "source_revision",
        "system_graph_sha256",
        "planner",
        "dependency_relation_kinds",
        "steps",
    }
    if set(plan) != required_fields:
        return (
            {"gate": "G3", "result": "FAIL", "findings": ["ExecutionPlan has unexpected or missing fields."]},
            empty_schedule,
        )
    findings: list[str] = []
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        findings.append("ExecutionPlan schema_version must be 1.")
    if not isinstance(plan["source_revision"], str) or not plan["source_revision"]:
        findings.append("ExecutionPlan must identify its source revision.")
    if not isinstance(plan["system_graph_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", plan["system_graph_sha256"]
    ):
        findings.append("ExecutionPlan must identify the SystemGraph SHA-256.")
    planner = plan["planner"]
    if (
        not isinstance(planner, dict)
        or set(planner) != {"name", "version"}
        or not all(isinstance(planner.get(key), str) and planner[key] for key in ("name", "version"))
    ):
        findings.append("ExecutionPlan planner must identify a name and version.")
    relation_kinds = plan["dependency_relation_kinds"]
    if not _is_string_list(relation_kinds, nonempty=True):
        findings.append("ExecutionPlan must declare dependency_relation_kinds.")
    elif len(set(relation_kinds)) != len(relation_kinds):
        findings.append("ExecutionPlan dependency_relation_kinds contains duplicates.")
    steps = plan["steps"]
    if not isinstance(steps, list) or not steps:
        findings.append("ExecutionPlan must contain at least one step.")
        steps = []

    step_by_id: dict[str, dict[str, Any]] = {}
    step_by_graph_node: dict[str, str] = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            findings.append(f"ExecutionPlan step at index {index} must be an object.")
            continue
        if set(step) != {"id", "graph_node", "depends_on", "recovery_point"}:
            findings.append(
                f"ExecutionPlan step at index {index} must contain only id, graph_node, depends_on, and recovery_point."
            )
        step_id = step.get("id")
        graph_node = step.get("graph_node")
        depends_on = step.get("depends_on")
        recovery_point = step.get("recovery_point")
        if not isinstance(step_id, str) or not step_id:
            findings.append(f"ExecutionPlan step at index {index} has no valid id.")
            continue
        if step_id in step_by_id:
            findings.append(f"Duplicate ExecutionPlan step id: {step_id}.")
        if not isinstance(graph_node, str) or not graph_node:
            findings.append(f"ExecutionPlan step {step_id} has no SystemGraph node.")
        elif graph_node in step_by_graph_node:
            findings.append(f"Multiple ExecutionPlan steps map to SystemGraph node {graph_node}.")
        else:
            step_by_graph_node[graph_node] = step_id
        if not _is_string_list(depends_on):
            findings.append(f"ExecutionPlan step {step_id} depends_on must be a string list.")
        if not isinstance(recovery_point, str) or not recovery_point.strip():
            findings.append(f"ExecutionPlan step {step_id} must declare a recovery point.")
        step_by_id[step_id] = step

    normalized_dependencies: list[tuple[str, str]] = []
    for step_id, step in step_by_id.items():
        depends_on = step.get("depends_on")
        if not _is_string_list(depends_on):
            continue
        if len(set(depends_on)) != len(depends_on):
            findings.append(f"ExecutionPlan step {step_id} has duplicate dependencies.")
        for dependency in depends_on:
            if dependency not in step_by_id:
                findings.append(f"ExecutionPlan step {step_id} depends on unknown step {dependency}.")
            elif dependency == step_id:
                findings.append(f"ExecutionPlan step {step_id} depends on itself.")
            else:
                normalized_dependencies.append((step_id, dependency))

    schedule: dict[str, Any] = {"execution_layers": [], "plan_sha256": _canonical_sha256(plan)}
    if findings:
        return {"gate": "G3", "result": "FAIL", "findings": findings}, schedule
    plan_order, plan_cycle = _topological_order(list(step_by_id), normalized_dependencies)
    if plan_cycle:
        return {"gate": "G3", "result": "FAIL", "findings": plan_cycle}, schedule

    if plan["source_revision"] != revision:
        return (
            {
                "gate": "G3",
                "result": "INCONCLUSIVE",
                "findings": [
                    f"ExecutionPlan revision {plan['source_revision']} does not match evaluated revision {revision}."
                ],
            },
            schedule,
        )
    if not isinstance(graph, dict):
        return (
            {"gate": "G3", "result": "HOLD", "findings": ["SystemGraph is unavailable for plan conformance."]},
            schedule,
        )
    if plan["system_graph_sha256"] != _canonical_sha256(graph):
        return (
            {"gate": "G3", "result": "INCONCLUSIVE", "findings": ["ExecutionPlan is not bound to the supplied SystemGraph digest."]},
            schedule,
        )
    if graph.get("revision") != revision:
        return (
            {
                "gate": "G3",
                "result": "INCONCLUSIVE",
                "findings": [
                    f"SystemGraph revision {graph.get('revision')} does not match evaluated revision {revision}."
                ],
            },
            schedule,
        )
    if g1_result != "PASS" or g2_result != "PASS":
        return (
            {
                "gate": "G3",
                "result": "HOLD",
                "findings": [f"G3 prerequisites are not PASS (G1={g1_result}, G2={g2_result})."],
            },
            schedule,
        )

    nodes = graph.get("nodes")
    relations = graph.get("relations")
    if not isinstance(nodes, list) or not isinstance(relations, list):
        return (
            {"gate": "G3", "result": "FAIL", "findings": ["SystemGraph nodes and relations must be arrays."]},
            schedule,
        )
    graph_nodes = {
        node.get("id"): node for node in nodes if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    required_services = {
        node_id for node_id, node in graph_nodes.items() if node.get("kind") == "service"
    }
    missing_services = sorted(required_services - set(step_by_graph_node))
    unknown_nodes = sorted(set(step_by_graph_node) - set(graph_nodes))
    non_service_nodes = sorted(
        graph_node
        for graph_node in step_by_graph_node
        if graph_node in graph_nodes and graph_nodes[graph_node].get("kind") != "service"
    )
    if missing_services:
        findings.append(f"ExecutionPlan omits service nodes: {missing_services}.")
    if unknown_nodes:
        findings.append(f"ExecutionPlan references unknown SystemGraph nodes: {unknown_nodes}.")
    if non_service_nodes:
        findings.append(f"ExecutionPlan steps must map to service nodes, not {non_service_nodes}.")

    dependency_relation_kinds = set(plan["dependency_relation_kinds"])
    graph_relation_kinds = graph.get("relation_kinds")
    if not isinstance(graph_relation_kinds, dict):
        findings.append("SystemGraph relation_kinds must be an object.")
        graph_relation_kinds = {}
    undeclared_kinds = sorted(dependency_relation_kinds - set(graph_relation_kinds))
    if undeclared_kinds:
        findings.append(f"ExecutionPlan declares unknown dependency relation kinds: {undeclared_kinds}.")
    expected_dependencies: set[tuple[str, str]] = set()
    for relation in relations:
        if not isinstance(relation, dict):
            continue
        if relation.get("kind") not in dependency_relation_kinds:
            continue
        source_step = step_by_graph_node.get(relation.get("source"))
        target_step = step_by_graph_node.get(relation.get("target"))
        if source_step is None or target_step is None:
            findings.append(
                f"Dependency relation {relation.get('source')} -[{relation.get('kind')}]-> "
                f"{relation.get('target')} is not represented by service steps."
            )
        else:
            expected_dependencies.add((source_step, target_step))
    actual_dependencies = set(normalized_dependencies)
    if actual_dependencies != expected_dependencies:
        findings.append(
            "ExecutionPlan dependencies do not exactly match the declared SystemGraph dependency relations."
        )

    if findings:
        return {"gate": "G3", "result": "FAIL", "findings": findings}, schedule

    remaining = {
        step_id: set(step.get("depends_on", []))
        for step_id, step in step_by_id.items()
    }
    layers: list[list[str]] = []
    while remaining:
        ready = sorted(step_id for step_id, dependencies in remaining.items() if not dependencies)
        if not ready:
            return (
                {"gate": "G3", "result": "FAIL", "findings": ["ExecutionPlan has no safe next execution layer."]},
                schedule,
            )
        layers.append(ready)
        for step_id in ready:
            del remaining[step_id]
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
    schedule["execution_layers"] = layers
    schedule["topological_order"] = plan_order
    return (
        {
            "gate": "G3",
            "result": "PASS",
            "findings": [
                f"Plan covers every graph service, preserves declared dependencies, and defines recovery for every step ({schedule['plan_sha256']})."
            ],
        },
        schedule,
    )


def evaluate_g4(
    test_output: str | None,
    exit_code: int | None,
    g3_result: str,
    error: str | None = None,
    source_revision: str | None = None,
    source_tree_clean: bool | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = ["cargo", "test", "--locked", "-p", "palaco-runtime", "-p", "palaco-kernel"]
    evidence: dict[str, Any] = {
        "command": command,
        "exit_code": exit_code,
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "run_id": run_id,
        "output_sha256": hashlib.sha256((test_output or "").encode("utf-8")).hexdigest()
        if test_output is not None
        else None,
        "scenarios": [],
    }
    if error:
        evidence["error"] = error
        return (
            {"gate": "G4", "result": "HOLD", "findings": [f"Runtime/kernel contract tests could not run: {error}"]},
            evidence,
        )
    if test_output is None or exit_code is None:
        return (
            {"gate": "G4", "result": "HOLD", "findings": ["Runtime/kernel contract test evidence is unavailable."]},
            evidence,
        )

    observed: dict[str, str] = {}
    pattern = re.compile(
        r"^test tests::("
        + "|".join(sorted(G4_SCENARIOS))
        + r") \.\.\. (ok|FAILED)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(test_output):
        observed[match.group(1)] = match.group(2)
    evidence["scenarios"] = [
        {"name": name, "result": observed.get(name, "missing")}
        for name in sorted(G4_SCENARIOS)
    ]

    failed = sorted(name for name, result in observed.items() if result != "ok")
    missing = sorted(G4_SCENARIOS - observed.keys())
    if exit_code != 0 or failed:
        findings = [f"Runtime/kernel contract tests failed (exit code {exit_code})."]
        if failed:
            findings.append(f"Failed scenarios: {failed}.")
        return {"gate": "G4", "result": "FAIL", "findings": findings}, evidence
    if missing:
        return (
            {"gate": "G4", "result": "HOLD", "findings": [f"Required runtime/kernel scenarios are missing: {missing}."]},
            evidence,
        )
    if not source_revision:
        return (
            {"gate": "G4", "result": "HOLD", "findings": ["Runtime/kernel test evidence is not bound to a source revision."]},
            evidence,
        )
    if source_tree_clean is not True:
        return (
            {
                "gate": "G4",
                "result": "INCONCLUSIVE",
                "findings": ["Runtime/kernel test evidence was produced from a dirty or unverifiable source tree."],
            },
            evidence,
        )
    if g3_result != "PASS":
        return (
            {
                "gate": "G4",
                "result": "HOLD",
                "findings": [f"Runtime/kernel scenarios pass, but G3 is {g3_result}; the governed execution plan is not validated."],
            },
            evidence,
        )
    return (
        {
            "gate": "G4",
            "result": "PASS",
            "findings": ["Runtime/kernel revalidation, escalation, and safe-state contract tests passed for the validated G3 input."],
        },
        evidence,
    )


def evaluate_g5(
    test_output: str | None,
    exit_code: int | None,
    g4_result: str,
    error: str | None = None,
    source_revision: str | None = None,
    source_tree_clean: bool | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "palaco-eventbus",
        "-p",
        "palaco-rio-core",
        "-p",
        "palaco-observatory",
    ]
    evidence: dict[str, Any] = {
        "command": command,
        "exit_code": exit_code,
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "run_id": run_id,
        "output_sha256": hashlib.sha256((test_output or "").encode("utf-8")).hexdigest()
        if test_output is not None
        else None,
        "scenarios": [],
    }
    if error:
        evidence["error"] = error
        return (
            {"gate": "G5", "result": "HOLD", "findings": [f"Event/observability contract tests could not run: {error}"]},
            evidence,
        )
    if test_output is None or exit_code is None:
        return (
            {"gate": "G5", "result": "HOLD", "findings": ["Event/observability contract test evidence is unavailable."]},
            evidence,
        )

    pattern = re.compile(
        r"^test (?:[\w]+::)*tests::("
        + "|".join(sorted(G5_SCENARIOS))
        + r") \.\.\. (ok|FAILED)$",
        re.MULTILINE,
    )
    observed = {match.group(1): match.group(2) for match in pattern.finditer(test_output)}
    evidence["scenarios"] = [
        {"name": name, "result": observed.get(name, "missing")}
        for name in sorted(G5_SCENARIOS)
    ]

    failed = sorted(name for name, result in observed.items() if result != "ok")
    missing = sorted(G5_SCENARIOS - observed.keys())
    if exit_code != 0 or failed:
        findings = [f"Event/observability contract tests failed (exit code {exit_code})."]
        if failed:
            findings.append(f"Failed scenarios: {failed}.")
        return {"gate": "G5", "result": "FAIL", "findings": findings}, evidence
    if missing:
        return (
            {"gate": "G5", "result": "HOLD", "findings": [f"Required event/observability scenarios are missing: {missing}."]},
            evidence,
        )
    if not source_revision:
        return (
            {"gate": "G5", "result": "HOLD", "findings": ["Event/observability test evidence is not bound to a source revision."]},
            evidence,
        )
    if source_tree_clean is not True:
        return (
            {
                "gate": "G5",
                "result": "INCONCLUSIVE",
                "findings": ["Event/observability test evidence was produced from a dirty or unverifiable source tree."],
            },
            evidence,
        )
    if g4_result != "PASS":
        return (
            {
                "gate": "G5",
                "result": "HOLD",
                "findings": [f"Required prior gate G4 is {g4_result}; the runtime/kernel contract is not validated."],
            },
            evidence,
        )
    return (
        {
            "gate": "G5",
            "result": "PASS",
            "findings": ["Event lifecycle, provenance, observability and authority-separation scenarios passed."],
        },
        evidence,
    )


def evaluate_g6(
    graph: Any,
    graph_error: str | None,
    inventory: list[dict[str, str]] | None,
    inventory_error: str | None,
    prior_results: list[str],
    source_revision: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence: dict[str, Any] = {
        "ruleset_version": G6_RULESET_VERSION,
        "source_revision": source_revision,
        "system_graph_revision": graph.get("revision") if isinstance(graph, dict) else None,
        "system_graph_sha256": _canonical_sha256(graph) if isinstance(graph, dict) else None,
        "inventory_sha256": _canonical_sha256(inventory) if inventory is not None else None,
        "inventory": inventory,
        "classifications": [],
    }
    if graph_error == "missing":
        return (
            {"gate": "G6", "result": "HOLD", "findings": ["SystemGraph artifact is not present."]},
            evidence,
        )
    if graph_error is not None:
        return (
            {"gate": "G6", "result": "FAIL", "findings": [f"SystemGraph could not be parsed: {graph_error}"]},
            evidence,
        )
    if inventory_error or inventory is None:
        return (
            {
                "gate": "G6",
                "result": "HOLD",
                "findings": [f"Implementation inventory is unavailable: {inventory_error or 'unknown error'}."],
            },
            evidence,
        )
    if not all(
        isinstance(package, dict)
        and isinstance(package.get("name"), str)
        and package["name"]
        and isinstance(package.get("manifest_path"), str)
        and package["manifest_path"]
        for package in inventory
    ):
        return (
            {"gate": "G6", "result": "HOLD", "findings": ["Implementation inventory has an invalid package record."]},
            evidence,
        )
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        return (
            {"gate": "G6", "result": "FAIL", "findings": ["SystemGraph nodes must be available for compliance analysis."]},
            evidence,
        )

    graph_paths: list[tuple[str, Path]] = []
    path_errors: list[str] = []
    for node in graph["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("source_paths"), list):
            path_errors.append("Graph node has no valid source_paths inventory.")
            continue
        for source_path in node["source_paths"]:
            if (
                not isinstance(source_path, str)
                or not source_path
                or source_path == "."
                or "\\" in source_path
                or Path(source_path).is_absolute()
                or ".." in Path(source_path).parts
            ):
                path_errors.append(f"Invalid graph source path: {source_path!r}.")
                continue
            resolved_path = (ROOT / source_path).resolve()
            try:
                resolved_path.relative_to(ROOT.resolve())
            except ValueError:
                path_errors.append(f"Graph source path escapes the repository: {source_path!r}.")
                continue
            if not resolved_path.exists():
                path_errors.append(f"Graph source path does not exist: {source_path}.")
                continue
            graph_paths.append((source_path, resolved_path))

    package_roots = {
        package["name"]: (ROOT / package["manifest_path"]).resolve().parent
        for package in inventory
    }
    covered: set[str] = set()
    for package_name, package_root in package_roots.items():
        for _, source_root in graph_paths:
            if not source_root.is_dir():
                continue
            try:
                package_root.relative_to(source_root)
                covered.add(package_name)
                break
            except ValueError:
                continue
    uncovered = sorted(set(package_roots) - covered)
    evidence["classifications"] = [
        {
            "class": "mandatory_violation",
            "rule": "G6-SOURCE-PATH-EXISTS",
            "result": "FAIL",
            "detail": detail,
        }
        for detail in path_errors
    ] + [
        {
            "class": "mandatory_violation",
            "rule": "G6-WORKSPACE-COVERAGE",
            "result": "FAIL",
            "component": package_name,
            "detail": "Workspace package is not covered by any declared SystemGraph source path.",
        }
        for package_name in uncovered
    ]

    if path_errors or uncovered:
        findings = [*path_errors]
        if uncovered:
            findings.append(f"Uncovered workspace packages: {uncovered}.")
        return {"gate": "G6", "result": "FAIL", "findings": findings}, evidence
    if not source_revision:
        return (
            {"gate": "G6", "result": "HOLD", "findings": ["Implementation inventory is not bound to a source revision."]},
            evidence,
        )
    if graph.get("revision") != source_revision:
        return (
            {
                "gate": "G6",
                "result": "INCONCLUSIVE",
                "findings": ["SystemGraph revision does not match the implementation inventory revision."],
            },
            evidence,
        )
    if len(prior_results) != 6 or any(result != "PASS" for result in prior_results):
        return (
            {
                "gate": "G6",
                "result": "HOLD",
                "findings": ["G0-G5 must all PASS before architecture compliance can PASS."],
            },
            evidence,
        )
    return (
        {
            "gate": "G6",
            "result": "PASS",
            "findings": [
                f"All {len(inventory)} workspace packages are covered by existing SystemGraph source paths."
            ],
        },
        evidence,
    )


def evaluate_g7(
    test_output: str | None,
    exit_code: int | None,
    prior_gates: list[dict[str, Any]],
    source_revision: str | None,
    source_tree_clean: bool | None,
    repository: str | None,
    scope_manifest: dict[str, Any] | None,
    scope_artifact: dict[str, str] | None,
    g4_evidence: dict[str, Any],
    g5_evidence: dict[str, Any],
    g6_evidence: dict[str, Any],
    system_graph_artifact: dict[str, str] | None,
    dependency_graph: dict[str, Any],
    execution_schedule: dict[str, Any],
    error: str | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = ["cargo", "test", "--locked", "--workspace"]
    evidence: dict[str, Any] = {
        "command": command,
        "exit_code": exit_code,
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "repository": repository,
        "scope": scope_manifest.get("scope") if isinstance(scope_manifest, dict) else None,
        "scope_sha256": scope_artifact.get("sha256") if scope_artifact else None,
        "system_graph_artifact_sha256": (
            system_graph_artifact.get("sha256")
            if isinstance(system_graph_artifact, dict)
            else None
        ),
        "dependency_graph_sha256": dependency_graph.get("sha256"),
        "execution_plan_sha256": execution_schedule.get("plan_sha256"),
        "run_id": run_id,
        "output_sha256": hashlib.sha256((test_output or "").encode("utf-8")).hexdigest()
        if test_output is not None
        else None,
        "reconciled_gates": [],
        "reconciliation": [],
        "scenarios": [],
    }

    pattern = re.compile(
        r"^test (?:[\w]+::)*tests::("
        + "|".join(sorted(G7_SCENARIOS))
        + r") \.\.\. (ok|FAILED)$",
        re.MULTILINE,
    )
    observed = (
        {match.group(1): match.group(2) for match in pattern.finditer(test_output)}
        if test_output is not None
        else {}
    )
    evidence["scenarios"] = [
        {"name": name, "result": observed.get(name, "missing")}
        for name in sorted(G7_SCENARIOS)
    ]

    failed_scenarios = sorted(name for name, result in observed.items() if result != "ok")
    missing_scenarios = sorted(G7_SCENARIOS - observed.keys())
    if error or (test_output is None or exit_code is None):
        return (
            {"gate": "G7", "result": "HOLD", "findings": [f"Integrated test evidence is unavailable: {error or 'no test output'}"]},
            evidence,
        )
    if exit_code != 0 or failed_scenarios:
        findings = [f"Integrated workspace tests failed (exit code {exit_code})."]
        if failed_scenarios:
            findings.append(f"Failed fail-closed scenarios: {failed_scenarios}.")
        return {"gate": "G7", "result": "FAIL", "findings": findings}, evidence
    if missing_scenarios:
        return (
            {"gate": "G7", "result": "HOLD", "findings": [f"Integrated fail-closed scenarios are missing: {missing_scenarios}."]},
            evidence,
        )

    expected_names = [f"G{index}" for index in range(7)]
    actual_names = [
        gate.get("gate") if isinstance(gate, dict) else None for gate in prior_gates
    ]
    if actual_names != expected_names:
        return (
            {"gate": "G7", "result": "HOLD", "findings": ["Consolidated evidence must contain exactly one ordered result for every gate G0-G6."]},
            evidence,
        )
    evidence["reconciled_gates"] = [
        {"gate": gate["gate"], "result": gate.get("result")} for gate in prior_gates
    ]
    failed_gates = [
        gate["gate"] for gate in prior_gates if gate.get("result") == "FAIL"
    ]
    if failed_gates:
        return (
            {"gate": "G7", "result": "FAIL", "findings": [f"Prior mandatory gates failed and remain unresolved: {failed_gates}."]},
            evidence,
        )
    blocked_gates = [
        gate["gate"] for gate in prior_gates if gate.get("result") != "PASS"
    ]
    if blocked_gates:
        return (
            {"gate": "G7", "result": "HOLD", "findings": [f"Prior gates are not all PASS: {blocked_gates}."]},
            evidence,
        )

    if (
        not source_revision
        or not isinstance(repository, str)
        or not repository
        or not isinstance(scope_manifest, dict)
        or not isinstance(scope_manifest.get("repository"), str)
        or not scope_manifest["repository"]
        or not isinstance(scope_manifest.get("scope"), str)
        or not scope_manifest["scope"]
        or scope_manifest["repository"].casefold() != repository.casefold()
        or not isinstance(scope_artifact, dict)
        or not isinstance(scope_artifact.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", scope_artifact["sha256"])
    ):
        return (
            {"gate": "G7", "result": "HOLD", "findings": ["Repository, source revision, and scoped manifest digest are required."]},
            evidence,
        )
    if source_tree_clean is not True:
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["Integrated evidence was not produced from a clean source tree."]},
            evidence,
        )
    if (
        not isinstance(system_graph_artifact, dict)
        or not isinstance(system_graph_artifact.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", system_graph_artifact["sha256"])
    ):
        return (
            {"gate": "G7", "result": "HOLD", "findings": ["SystemGraph artifact digest is unavailable for reconciliation."]},
            evidence,
        )

    reconciliation = [
        ("G4 source revision", g4_evidence.get("source_revision"), source_revision),
        ("G5 source revision", g5_evidence.get("source_revision"), source_revision),
        ("G6 source revision", g6_evidence.get("source_revision"), source_revision),
        ("G6 graph revision", g6_evidence.get("system_graph_revision"), source_revision),
        ("G6 graph digest", g6_evidence.get("system_graph_artifact_sha256"), system_graph_artifact["sha256"]),
    ]
    evidence["reconciliation"] = [
        {"item": label, "observed": observed_value, "expected": expected_value}
        for label, observed_value, expected_value in reconciliation
    ]
    if any(not observed_value or observed_value != expected_value for _, observed_value, expected_value in reconciliation):
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["G0-G6 evidence is missing or bound to conflicting revisions/artifacts."]},
            evidence,
        )
    if g4_evidence.get("source_tree_clean") is not True or g5_evidence.get("source_tree_clean") is not True:
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["Prior runtime/event evidence was not produced from a clean source tree."]},
            evidence,
        )
    if not isinstance(run_id, str) or not run_id:
        return (
            {"gate": "G7", "result": "HOLD", "findings": ["A CI run ID is required for integrated evidence."]},
            evidence,
        )
    prior_run_ids = [g4_evidence.get("run_id"), g5_evidence.get("run_id"), run_id]
    if any(not isinstance(value, str) or not value for value in prior_run_ids) or len(set(prior_run_ids)) > 1:
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["Integrated evidence spans conflicting CI run IDs."]},
            evidence,
        )
    inventory_digest = g6_evidence.get("inventory_sha256")
    if not isinstance(inventory_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", inventory_digest):
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["G6 implementation inventory digest is unavailable or malformed."]},
            evidence,
        )
    if (
        not isinstance(dependency_graph.get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", dependency_graph["sha256"])
        or not isinstance(execution_schedule.get("plan_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", execution_schedule["plan_sha256"])
    ):
        return (
            {"gate": "G7", "result": "INCONCLUSIVE", "findings": ["Dependency or ExecutionPlan digest is unavailable for evidence reconciliation."]},
            evidence,
        )
    return (
        {
            "gate": "G7",
            "result": "PASS",
            "findings": ["G0-G6 evidence reconciles to the same repository, scope, revision and CI run; integrated fail-closed scenarios passed."],
        },
        evidence,
    )


def evaluate_g8(
    checklist_text: str | None,
    threat_model_text: str | None,
    checklist_error: str | None,
    threat_model_error: str | None,
    source_revision: str | None,
    source_tree_clean: bool | None,
    checklist_artifact: dict[str, str] | None,
    threat_model_artifact: dict[str, str] | None,
    prior_gates: list[dict[str, Any]],
    security_environment: dict[str, Any],
    dependency_audit: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence: dict[str, Any] = {
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "checklist": checklist_artifact,
        "threat_model": threat_model_artifact,
        "security_environment": security_environment,
        "dependency_audit": dependency_audit,
        "controls": [],
    }
    if checklist_error == "missing":
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Required validation/security_checklist.md is not present."]},
            evidence,
        )
    if checklist_error or checklist_text is None:
        return (
            {"gate": "G8", "result": "FAIL", "findings": [f"Security checklist could not be read: {checklist_error or 'unknown error'}."]},
            evidence,
        )
    if threat_model_error or threat_model_text is None:
        return (
            {"gate": "G8", "result": "HOLD", "findings": [f"Core Alpha threat model is unavailable: {threat_model_error or 'unknown error'}."]},
            evidence,
        )
    controls: dict[str, dict[str, str]] = {}
    for line in checklist_text.splitlines():
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) != 3 or columns[0] not in G8_REQUIRED_CONTROLS:
            continue
        control, status, reference = columns
        if control in controls:
            return (
                {"gate": "G8", "result": "FAIL", "findings": [f"Security checklist contains duplicate control {control}."]},
                evidence,
            )
        controls[control] = {"status": status, "evidence": reference}

    evidence["controls"] = [
        {
            "control": control,
            "status": item["status"],
            "evidence": item["evidence"],
            "evidence_verified": False,
        }
        for control, item in sorted(controls.items())
    ]
    missing_controls = sorted(G8_REQUIRED_CONTROLS - controls.keys())
    if missing_controls:
        return (
            {"gate": "G8", "result": "HOLD", "findings": [f"Security checklist omits required controls: {missing_controls}."]},
            evidence,
        )
    invalid = sorted(
        control
        for control, item in controls.items()
        if item["status"] not in {"PASS", "FAIL", "HOLD", "OPEN"}
    )
    if invalid:
        return (
            {"gate": "G8", "result": "FAIL", "findings": [f"Security checklist has invalid statuses for controls: {invalid}."]},
            evidence,
        )

    if "**Scope:** PALACO Core Alpha" not in checklist_text:
        return (
            {"gate": "G8", "result": "FAIL", "findings": ["Security checklist does not identify the required PALACO Core Alpha scope."]},
            evidence,
        )
    if "core alpha" not in threat_model_text.lower():
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Threat model does not explicitly identify PALACO Core Alpha scope."]},
            evidence,
        )
    if "Assets:" not in threat_model_text or "Trust boundaries:" not in threat_model_text:
        return (
            {"gate": "G8", "result": "FAIL", "findings": ["Threat-model artifact is missing required asset or trust-boundary analysis."]},
            evidence,
        )

    evidence["controls"] = []
    for control in sorted(controls):
        item = controls[control]
        result: dict[str, Any] = {
            "control": control,
            "status": item["status"],
            "evidence": item["evidence"],
            "evidence_verified": False,
        }
        if item["status"] == "PASS":
            match = re.fullmatch(r"([^@]+)@([0-9a-f]{64})", item["evidence"])
            if not match:
                return (
                    {"gate": "G8", "result": "FAIL", "findings": [f"PASS control {control} must reference evidence as path@sha256."]},
                    {**evidence, "controls": [*evidence["controls"], result]},
                )
            path_text, expected_digest = match.groups()
            evidence_path = Path(path_text)
            if evidence_path.is_absolute() or "\\" in path_text or ".." in evidence_path.parts:
                return (
                    {"gate": "G8", "result": "FAIL", "findings": [f"Evidence path for {control} is not repository-relative."]},
                    {**evidence, "controls": [*evidence["controls"], result]},
                )
            candidate = (ROOT / evidence_path).resolve()
            try:
                candidate.relative_to(ROOT.resolve())
            except ValueError:
                return (
                    {"gate": "G8", "result": "FAIL", "findings": [f"Evidence path for {control} escapes the repository."]},
                    {**evidence, "controls": [*evidence["controls"], result]},
                )
            if not candidate.is_file():
                return (
                    {"gate": "G8", "result": "HOLD", "findings": [f"Evidence artifact for {control} is missing: {path_text}."]},
                    {**evidence, "controls": [*evidence["controls"], result]},
                )
            actual_digest = digest(candidate)
            result["observed_sha256"] = actual_digest
            if actual_digest != expected_digest:
                return (
                    {"gate": "G8", "result": "FAIL", "findings": [f"Evidence digest mismatch for {control}."]},
                    {**evidence, "controls": [*evidence["controls"], result]},
                )
            result["evidence_verified"] = True
        evidence["controls"].append(result)

    failed_controls = sorted(control for control, item in controls.items() if item["status"] == "FAIL")
    if failed_controls:
        return (
            {"gate": "G8", "result": "FAIL", "findings": [f"Security controls are marked FAIL: {failed_controls}."]},
            evidence,
        )
    expected_gates = [f"G{index}" for index in range(8)]
    actual_gates = [gate.get("gate") if isinstance(gate, dict) else None for gate in prior_gates]
    if actual_gates != expected_gates:
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Consolidated evidence must contain ordered G0-G7 results."]},
            evidence,
        )
    prior_failures = [gate["gate"] for gate in prior_gates if gate.get("result") == "FAIL"]
    if prior_failures:
        return (
            {"gate": "G8", "result": "FAIL", "findings": [f"Prior mandatory gates failed and remain unresolved: {prior_failures}."]},
            evidence,
        )
    open_controls = sorted(control for control, item in controls.items() if item["status"] in {"OPEN", "HOLD"})
    if open_controls:
        return (
            {"gate": "G8", "result": "HOLD", "findings": [f"Security controls remain unresolved: {open_controls}."]},
            evidence,
        )
    if not source_revision or source_tree_clean is not True:
        return (
            {"gate": "G8", "result": "INCONCLUSIVE", "findings": ["Security evidence is not bound to a clean source revision."]},
            evidence,
        )
    prior_blockers = [gate["gate"] for gate in prior_gates if gate.get("result") != "PASS"]
    if prior_blockers:
        return (
            {"gate": "G8", "result": "HOLD", "findings": [f"Prior gates are not all PASS: {prior_blockers}."]},
            evidence,
        )
    if not security_environment.get("dependency_audit_available"):
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Cargo dependency-audit tooling is unavailable."]},
            evidence,
        )
    if dependency_audit.get("result") != "PASS":
        result = dependency_audit.get("result")
        status = result if result in {"FAIL", "INCONCLUSIVE"} else "HOLD"
        return (
            {"gate": "G8", "result": status, "findings": [f"Cargo dependency audit is not PASS: {dependency_audit.get('finding', 'no successful audit evidence')}."]},
            evidence,
        )
    if (
        dependency_audit.get("source_revision") != source_revision
        or dependency_audit.get("source_tree_clean") is not True
        or not isinstance(dependency_audit.get("output_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", dependency_audit["output_sha256"])
    ):
        return (
            {"gate": "G8", "result": "INCONCLUSIVE", "findings": ["Dependency-audit output is not bound to the clean evaluated revision."]},
            evidence,
        )
    if not security_environment.get("dependency_audit_config_present"):
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Dependency/supply-chain policy configuration is absent."]},
            evidence,
        )
    if not security_environment.get("security_workflow_present"):
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Dedicated security workflow is absent."]},
            evidence,
        )
    if not checklist_artifact or not threat_model_artifact:
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Checklist and threat-model digests are required."]},
            evidence,
        )
    if "OPEN" in threat_model_text or "production blocked" in threat_model_text.lower():
        return (
            {"gate": "G8", "result": "HOLD", "findings": ["Threat model retains open production-blocking risks."]},
            evidence,
        )
    return (
        {"gate": "G8", "result": "PASS", "findings": ["Required security controls and evidence are complete for the bound source revision."]},
        evidence,
    )


def evaluate_g9(
    release_text: str | None,
    release_error: str | None,
    source_revision: str | None,
    expected_repository: str | None,
    source_tree_clean: bool | None,
    prior_gates: list[dict[str, Any]],
    release_artifact: dict[str, str] | None,
    release_evidence_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence: dict[str, Any] = {
        "repository": expected_repository,
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "evidence_root": "repository" if release_evidence_root.resolve() == ROOT.resolve() else "external evidence bundle",
        "release_checklist": release_artifact,
        "artifact": None,
        "evidence_report": None,
        "attestation": None,
        "decision_authority": None,
        "decision_record": None,
        "decision": None,
        "release_eligible": False,
        "release_approval_claimed": False,
        "decision_authority_authenticated": False,
        "attestation_binding_verified": False,
        "attestation_authentication_verified": False,
        "evidence_report_g9_result": None,
    }
    if release_error == "missing":
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["Required validation/release_validation.md is not present."]},
            evidence,
        )
    if release_error or release_text is None:
        return (
            {"gate": "G9", "result": "FAIL", "findings": [f"Release checklist could not be read: {release_error or 'unknown error'}."]},
            evidence,
        )

    fields: dict[str, str] = {}
    header_seen = False
    for line in release_text.splitlines():
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if columns == ["Field", "Value"]:
            header_seen = True
            continue
        if columns and all(re.fullmatch(r":?-{3,}:?", column) for column in columns):
            continue
        if not header_seen:
            continue
        if len(columns) != 2:
            return (
                {"gate": "G9", "result": "FAIL", "findings": ["Release checklist table rows must contain exactly a field and value."]},
                evidence,
            )
        if columns[0] in fields:
            return (
                {"gate": "G9", "result": "FAIL", "findings": [f"Release checklist contains duplicate field {columns[0]}."]},
                evidence,
            )
        fields[columns[0]] = columns[1]

    if not header_seen:
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Release checklist must use a Field/Value table."]},
            evidence,
        )
    required = {
        "source_revision",
        "artifact",
        "evidence_report",
        "attestation",
        "decision_authority",
        "decision_record",
        "decision",
    }
    missing = sorted(required - fields.keys())
    if missing:
        return (
            {"gate": "G9", "result": "HOLD", "findings": [f"Release checklist omits required fields: {missing}."]},
            evidence,
        )

    evidence["decision_authority"] = fields["decision_authority"]
    evidence["decision_record"] = fields["decision_record"]
    evidence["decision"] = fields["decision"].upper()
    if not fields["decision_authority"].strip() or not fields["decision_record"].strip():
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["Release decision authority and decision record must be explicit."]},
            evidence,
        )
    if evidence["decision"] not in {"APPROVE", "REJECT"}:
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["Release decision must be recorded as APPROVE or REJECT."]},
            evidence,
        )
    evidence["release_approval_claimed"] = evidence["decision"] == "APPROVE"

    if (
        not source_revision
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_revision)
        or not expected_repository
        or source_tree_clean is not True
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Release evidence is not bound to a clean repository and full immutable source object ID."]},
            evidence,
        )
    if fields["source_revision"] != source_revision:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Release checklist source revision does not match the evaluated revision."]},
            evidence,
        )

    expected_gates = [f"G{index}" for index in range(9)]
    actual_gates = [gate.get("gate") if isinstance(gate, dict) else None for gate in prior_gates]
    if actual_gates != expected_gates:
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["Consolidated evidence must contain ordered G0-G8 results."]},
            evidence,
        )
    invalid_gates = [
        gate["gate"]
        for gate in prior_gates
        if not isinstance(gate.get("result"), str)
        or gate["result"] not in GATE_RESULTS
    ]
    if invalid_gates:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": [f"Prior gate results are invalid or unverifiable: {invalid_gates}."]},
            evidence,
        )
    failed_gates = [gate["gate"] for gate in prior_gates if gate["result"] == "FAIL"]
    if failed_gates:
        return (
            {"gate": "G9", "result": "FAIL", "findings": [f"Prior mandatory gates failed and remain unresolved: {failed_gates}."]},
            evidence,
        )
    current_blocked_gates = [
        gate["gate"] for gate in prior_gates if gate["result"] != "PASS"
    ]

    def verified_artifact(field: str, label: str) -> tuple[dict[str, Any] | None, str | None, str | None]:
        value = fields[field]
        match = re.fullmatch(r"([^@]+)@([0-9a-f]{64})", value)
        if not match:
            return None, None, f"{label} must reference evidence as relative-path@sha256."
        path_text, expected_digest = match.groups()
        artifact_path = Path(path_text)
        if (
            artifact_path.is_absolute()
            or "\\" in path_text
            or ".." in artifact_path.parts
            or any(ord(character) < 32 or ord(character) == 127 for character in path_text)
        ):
            return None, None, f"{label} path must be relative to the release evidence directory."
        try:
            candidate = (release_evidence_root / artifact_path).resolve()
        except (OSError, RuntimeError) as error:
            return None, None, f"{label} path could not be resolved: {error}."
        try:
            candidate.relative_to(release_evidence_root.resolve())
        except ValueError:
            return None, None, f"{label} path escapes the release evidence directory."
        try:
            if not candidate.is_file():
                return None, f"{label} artifact is missing: {path_text}.", None
        except (OSError, ValueError, RuntimeError) as error:
            return None, None, f"{label} path could not be inspected: {error}."
        try:
            observed_digest = digest(candidate)
        except OSError:
            return None, f"{label} artifact could not be read: {path_text}.", None
        if observed_digest != expected_digest:
            return None, None, f"{label} digest mismatch."
        return {"path": path_text, "sha256": observed_digest}, None, None

    for field, label, evidence_key in (
        ("artifact", "Release artifact", "artifact"),
        ("evidence_report", "G0-G8 evidence report", "evidence_report"),
        ("attestation", "Release attestation", "attestation"),
    ):
        verified, missing_error, invalid_error = verified_artifact(field, label)
        evidence[evidence_key] = verified
        if invalid_error:
            return (
                {"gate": "G9", "result": "FAIL", "findings": [invalid_error]},
                evidence,
            )
        if missing_error:
            return (
                {"gate": "G9", "result": "HOLD", "findings": [missing_error]},
                evidence,
            )

    if evidence["evidence_report"] is None:
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["G0-G8 evidence report is unavailable."]},
            evidence,
        )
    evidence_path = release_evidence_root / evidence["evidence_report"]["path"]
    report, report_error = read_json(evidence_path)
    if report_error or not isinstance(report, dict):
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced G0-G8 evidence report is not valid JSON."]},
            evidence,
        )
    validator = report.get("validator")
    if (
        type(report.get("format_version")) is not int
        or report.get("format_version") != 1
        or not isinstance(validator, dict)
        or validator.get("name") != "PVC-001 G0-G9 validator"
        or validator.get("version") != VALIDATOR_VERSION
    ):
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced evidence report format or validator identity is unsupported."]},
            evidence,
        )
    generated_at = report.get("generated_at")
    if not isinstance(generated_at, str):
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced evidence report has no valid generation timestamp."]},
            evidence,
        )
    try:
        timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError:
        timestamp = None
    if timestamp is None or timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced evidence report generation timestamp must be timezone-aware ISO 8601."]},
            evidence,
        )
    if report.get("revision") != source_revision:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G0-G8 evidence report is for a different source revision."]},
            evidence,
        )
    if report.get("repository") != expected_repository:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G0-G8 evidence report is for a different or unidentified repository."]},
            evidence,
        )
    report_artifacts = report.get("artifacts")
    required_artifacts = (
        "scope",
        "system_graph",
        "system_graph_schema",
        "dependency_ordering",
        "execution_plan",
        "execution_plan_schema",
    )
    if not isinstance(report_artifacts, dict) or any(
        not isinstance(report_artifacts.get(key), dict)
        or not isinstance(report_artifacts[key].get("path"), str)
        or not report_artifacts[key]["path"]
        or Path(report_artifacts[key]["path"]).is_absolute()
        or "\\" in report_artifacts[key]["path"]
        or ".." in Path(report_artifacts[key]["path"]).parts
        or any(ord(character) < 32 or ord(character) == 127 for character in report_artifacts[key]["path"])
        or not isinstance(report_artifacts[key].get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", report_artifacts[key]["sha256"])
        for key in required_artifacts
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G0-G3 input artifact paths or digests are missing or malformed."]},
            evidence,
        )
    for key in required_artifacts:
        artifact = report_artifacts[key]
        try:
            artifact_path = (ROOT / artifact["path"]).resolve()
            artifact_path.relative_to(ROOT.resolve())
            artifact_exists = artifact_path.is_file()
            observed_digest = digest(artifact_path) if artifact_exists else None
        except (OSError, RuntimeError, ValueError):
            artifact_exists = False
            observed_digest = None
        if not artifact_exists or observed_digest != artifact["sha256"]:
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": [f"Referenced G0-G3 input artifact is missing or its digest does not match the evaluated checkout: {key}."]},
                evidence,
            )
    bound_inputs: dict[str, dict[str, Any]] = {}
    for key in required_artifacts:
        artifact = report_artifacts[key]
        parsed, parse_error = read_json(ROOT / artifact["path"])
        if parse_error or not isinstance(parsed, dict):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": [f"Referenced G0-G3 input is not a valid JSON object: {key}."]},
                evidence,
            )
        bound_inputs[key] = parsed
    scope_input = bound_inputs["scope"]
    graph_input = bound_inputs["system_graph"]
    ordering_input = bound_inputs["dependency_ordering"]
    plan_input = bound_inputs["execution_plan"]
    graph_digest = _canonical_sha256(graph_input)
    if (
        type(scope_input.get("schema_version")) is not int
        or scope_input.get("schema_version") != 1
        or scope_input.get("repository") != expected_repository
        or graph_input.get("revision") != source_revision
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Bound G0/G1 inputs do not identify the evaluated repository and revision."]},
            evidence,
        )
    dependency_graph = report.get("dependency_graph")
    if not isinstance(dependency_graph, dict):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G2 dependency graph is missing or malformed."]},
            evidence,
        )
    observed_dependency_digest = dependency_graph.get("sha256")
    digest_payload = {key: value for key, value in dependency_graph.items() if key != "sha256"}
    if (
        not isinstance(observed_dependency_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", observed_dependency_digest)
        or _dependency_graph_digest(digest_payload) != observed_dependency_digest
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G2 dependency graph digest does not match its contents."]},
            evidence,
        )
    schedule = report.get("execution_schedule")
    if not isinstance(schedule, dict):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G3 execution schedule is missing or malformed."]},
            evidence,
        )
    layers = schedule.get("execution_layers")
    topological_order = schedule.get("topological_order")
    flattened_layers = (
        [step for layer in layers for step in layer]
        if isinstance(layers, list)
        and all(
            isinstance(layer, list)
            and layer
            and all(isinstance(step, str) and step for step in layer)
            for layer in layers
        )
        else None
    )
    valid_topological_order = (
        isinstance(topological_order, list)
        and all(isinstance(step, str) and step for step in topological_order)
    )
    plan_digest = schedule.get("plan_sha256")
    if (
        not isinstance(plan_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", plan_digest)
        or not isinstance(layers, list)
        or not layers
        or flattened_layers is None
        or len(flattened_layers) != len(set(flattened_layers))
        or any(layer != sorted(layer) for layer in layers)
        or not valid_topological_order
        or len(topological_order) != len(set(topological_order))
        or set(topological_order) != set(flattened_layers)
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G3 plan digest or deterministic execution schedule is missing, malformed or inconsistent."]},
            evidence,
        )
    if (
        plan_input.get("source_revision") != source_revision
        or plan_input.get("system_graph_sha256") != graph_digest
        or _canonical_sha256(plan_input) != plan_digest
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Bound G3 ExecutionPlan does not match its source revision, SystemGraph or reported plan digest."]},
            evidence,
        )
    startup_constraints = ordering_input.get("startup_constraints")
    shutdown_constraints = ordering_input.get("shutdown_constraints")
    approved_by = ordering_input.get("approved_by")
    decision_ref = ordering_input.get("decision_ref")
    if (
        ordering_input.get("status") != "approved"
        or ordering_input.get("graph_sha256") != observed_dependency_digest
        or not isinstance(startup_constraints, list)
        or not isinstance(shutdown_constraints, list)
        or not isinstance(approved_by, str)
        or not approved_by
        or not isinstance(decision_ref, str)
        or not decision_ref
        or ordering_input.get("approval_sha256")
        != _ordering_approval_digest(
            observed_dependency_digest,
            startup_constraints,
            shutdown_constraints,
            approved_by,
            decision_ref,
        )
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Bound G2 ordering approval does not match the derived dependency graph or its recorded constraints."]},
            evidence,
        )
    architecture = report.get("architecture_compliance")
    if (
        not isinstance(architecture, dict)
        or architecture.get("source_revision") != source_revision
        or architecture.get("system_graph_revision") != source_revision
        or architecture.get("system_graph_sha256") != graph_digest
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G1/G6 architecture evidence is not bound to the report revision and a valid SystemGraph digest."]},
            evidence,
        )
    report_gates = report.get("gates")
    report_gate_names = (
        [gate.get("gate") if isinstance(gate, dict) else None for gate in report_gates]
        if isinstance(report_gates, list)
        else []
    )
    if report_gate_names not in (expected_gates, [*expected_gates, "G9"]):
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced evidence report does not contain ordered G0-G8 results."]},
            evidence,
        )
    malformed_gates = [
        gate["gate"]
        for gate in report_gates
        if not isinstance(gate.get("findings"), list)
        or any(not isinstance(finding, str) for finding in gate["findings"])
    ]
    if malformed_gates:
        return (
            {"gate": "G9", "result": "FAIL", "findings": [f"Referenced evidence report has malformed gate findings: {malformed_gates}."]},
            evidence,
        )
    if len(report_gates) == 10:
        report_g9 = report_gates[9]
        if (
            not isinstance(report_g9.get("result"), str)
            or report_g9["result"] not in GATE_RESULTS
        ):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced evidence report has an unverifiable G9 result."]},
                evidence,
            )
        evidence["evidence_report_g9_result"] = report_g9["result"]
    report_invalid = [
        gate["gate"]
        for gate in report_gates[:9]
        if not isinstance(gate.get("result"), str)
        or gate["result"] not in GATE_RESULTS
    ]
    if report_invalid:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": [f"Referenced evidence report has unverifiable gate results: {report_invalid}."]},
            evidence,
        )
    report_failures = [gate["gate"] for gate in report_gates[:9] if gate.get("result") == "FAIL"]
    if report_failures:
        return (
            {"gate": "G9", "result": "FAIL", "findings": [f"Referenced evidence report records prior failures: {report_failures}."]},
            evidence,
        )
    report_blockers = [
        gate["gate"] for gate in report_gates[:9] if gate.get("result") != "PASS"
    ]
    blocked_gates = list(dict.fromkeys(current_blocked_gates + report_blockers))
    if blocked_gates:
        return (
            {"gate": "G9", "result": "HOLD", "findings": [f"Current or referenced prior gates are not all PASS: {blocked_gates}."]},
            evidence,
        )
    current_scope_result = evaluate_g0(
        scope_input,
        expected_repository,
        source_revision,
        _workspace_components(),
        not source_tree_clean,
    )
    current_graph_result = evaluate_g1(
        graph_input, scope_input, source_revision
    )
    dependency_nodes, dependency_edges, dependency_error = _workspace_dependency_graph()
    if dependency_error:
        current_ordering_result, current_dependency_graph = evaluate_g2(
            None, None, ordering_input
        )
    else:
        current_ordering_result, current_dependency_graph = evaluate_g2(
            dependency_nodes,
            dependency_edges,
            ordering_input,
        )
    current_plan_result, current_schedule = evaluate_g3(
        graph_input,
        plan_input,
        source_revision,
        current_graph_result["result"],
        current_ordering_result["result"],
    )
    recomputed_gates = (
        current_scope_result,
        current_graph_result,
        current_ordering_result,
        current_plan_result,
    )
    if any(
        report_gates[index].get("result") != recomputed["result"]
        for index, recomputed in enumerate(recomputed_gates)
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G0-G3 gate results do not match recomputation from the bound inputs and current workspace."]},
            evidence,
        )
    if current_dependency_graph != dependency_graph or any(
        schedule.get(key) != current_schedule.get(key)
        for key in ("execution_layers", "topological_order", "plan_sha256")
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G2/G3 derived evidence does not match recomputation from the bound inputs and current workspace."]},
            evidence,
        )
    evidence_keys = (
        "runtime_kernel_tests",
        "event_observability_tests",
        "integrated_validation",
    )
    integrated_evidence = [report.get(key) for key in evidence_keys]
    integrated_run_ids = [
        report.get("run_id"),
        *(
            item.get("run_id") if isinstance(item, dict) else None
            for item in integrated_evidence
        ),
    ]
    if any(not isinstance(run_id, str) or not run_id for run_id in integrated_run_ids) or len(
        set(integrated_run_ids)
    ) != 1:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced evidence report has missing or conflicting G4-G7 CI run IDs."]},
            evidence,
        )
    if any(
        not isinstance(item, dict)
        or item.get("source_revision") != source_revision
        or item.get("source_tree_clean") is not True
        or type(item.get("exit_code")) is not int
        or item["exit_code"] != 0
        or not isinstance(item.get("output_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", item["output_sha256"])
        for item in integrated_evidence
    ) or integrated_evidence[2].get("repository") != expected_repository:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G4-G7 test evidence has missing or conflicting revision, cleanliness, repository, exit-code or output-digest metadata."]},
            evidence,
        )
    for item, expected_scenarios in zip(
        integrated_evidence, (G4_SCENARIOS, G5_SCENARIOS, G7_SCENARIOS)
    ):
        scenarios = item.get("scenarios")
        if not isinstance(scenarios, list) or any(
            not isinstance(scenario, dict)
            or not isinstance(scenario.get("name"), str)
            or not isinstance(scenario.get("result"), str)
            for scenario in scenarios
        ):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G4-G7 PASS gates have malformed scenario evidence."]},
                evidence,
            )
        observed_scenarios = {
            scenario["name"]: scenario["result"] for scenario in scenarios
        }
        if (
            len(scenarios) != len(expected_scenarios)
            or len(observed_scenarios) != len(expected_scenarios)
            or observed_scenarios.keys() != expected_scenarios
            or any(result != "ok" for result in observed_scenarios.values())
        ):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G4-G7 PASS gates do not reconcile with complete, successful required scenario evidence."]},
                evidence,
            )
    integrated = integrated_evidence[2]
    required_reconciliation = {
        "G4 source revision": source_revision,
        "G5 source revision": source_revision,
        "G6 source revision": source_revision,
        "G6 graph revision": source_revision,
        "G6 graph digest": report_artifacts["system_graph"]["sha256"],
    }
    reconciliation_records = integrated.get("reconciliation")
    observed_reconciliation = (
        {
            entry.get("item"): (entry.get("observed"), entry.get("expected"))
            for entry in reconciliation_records
            if isinstance(entry, dict) and isinstance(entry.get("item"), str)
        }
        if isinstance(reconciliation_records, list)
        else {}
    )
    if (
        integrated.get("scope_sha256") != report_artifacts["scope"]["sha256"]
        or integrated.get("system_graph_artifact_sha256")
        != report_artifacts["system_graph"]["sha256"]
        or integrated.get("dependency_graph_sha256") != observed_dependency_digest
        or integrated.get("execution_plan_sha256") != plan_digest
        or len(observed_reconciliation) != len(required_reconciliation)
        or set(observed_reconciliation) != set(required_reconciliation)
        or any(
            observed != expected or expected != required_reconciliation[label]
            for label, (observed, expected) in observed_reconciliation.items()
        )
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G7 reconciliation does not bind the scope, SystemGraph, dependency graph and execution plan evidence consistently."]},
            evidence,
        )
    security = report.get("security_validation")
    security_environment = (
        security.get("security_environment") if isinstance(security, dict) else None
    )
    dependency_audit = (
        security.get("dependency_audit") if isinstance(security, dict) else None
    )
    control_records = security.get("controls") if isinstance(security, dict) else None
    if (
        not isinstance(security, dict)
        or security.get("source_revision") != source_revision
        or security.get("source_tree_clean") is not True
        or not isinstance(security_environment, dict)
        or any(
            security_environment.get(name) is not True
            for name in (
                "dependency_audit_available",
                "dependency_audit_config_present",
                "security_workflow_present",
            )
        )
        or not isinstance(dependency_audit, dict)
        or dependency_audit.get("result") != "PASS"
        or dependency_audit.get("source_revision") != source_revision
        or dependency_audit.get("source_tree_clean") is not True
        or dependency_audit.get("run_id") != report.get("run_id")
        or type(dependency_audit.get("exit_code")) is not int
        or dependency_audit.get("exit_code") != 0
        or not isinstance(dependency_audit.get("output_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", dependency_audit["output_sha256"])
        or not isinstance(control_records, list)
    ):
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G8 security evidence has missing or conflicting revision, cleanliness, environment or dependency-audit metadata."]},
            evidence,
        )
    controls_by_name = {
        control.get("control"): control
        for control in control_records
        if isinstance(control, dict) and isinstance(control.get("control"), str)
    }
    if len(controls_by_name) != len(control_records) or controls_by_name.keys() != G8_REQUIRED_CONTROLS:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G8 evidence does not contain exactly one record for each required security control."]},
            evidence,
        )
    for control in controls_by_name.values():
        reference = control.get("evidence")
        match = re.fullmatch(r"[^@]+@([0-9a-f]{64})", reference) if isinstance(reference, str) else None
        if (
            control.get("status") != "PASS"
            or control.get("evidence_verified") is not True
            or match is None
            or control.get("observed_sha256") != match.group(1)
        ):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G8 control evidence is incomplete or does not reconcile with its verified digest."]},
                evidence,
            )
    for key in ("checklist", "threat_model"):
        artifact = security.get(key)
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("path"), str)
            or not artifact["path"]
            or not isinstance(artifact.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
        ):
            return (
                {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Referenced G8 security checklist or threat-model digest is unavailable or malformed."]},
                evidence,
            )
    attestation_path = release_evidence_root / evidence["attestation"]["path"]
    attestation, attestation_error = read_json(attestation_path)
    if attestation_error or not isinstance(attestation, dict):
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Referenced release attestation is not valid JSON."]},
            evidence,
        )
    if attestation.get("source_revision") != source_revision:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Release attestation is for a different source revision."]},
            evidence,
        )
    if attestation.get("repository") != expected_repository:
        return (
            {"gate": "G9", "result": "INCONCLUSIVE", "findings": ["Release attestation is for a different or unidentified repository."]},
            evidence,
        )
    if attestation.get("artifact_sha256") != evidence["artifact"]["sha256"]:
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Release attestation does not bind the checked artifact digest."]},
            evidence,
        )
    if attestation.get("evidence_report_sha256") != evidence["evidence_report"]["sha256"]:
        return (
            {"gate": "G9", "result": "FAIL", "findings": ["Release attestation does not bind the checked G0-G8 evidence report."]},
            evidence,
        )
    evidence["attestation_binding_verified"] = True
    if evidence["decision"] == "REJECT":
        return (
            {"gate": "G9", "result": "HOLD", "findings": ["Release candidate decision is REJECT; release eligibility is not established."]},
            evidence,
        )
    evidence["release_eligible"] = True
    return (
        {"gate": "G9", "result": "PASS", "findings": ["Release candidate is technically eligible; the APPROVE entry is a recorded claim, not authenticated authority."]},
        evidence,
    )


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeDecodeError) as error:
        return None, str(error)


def _security_environment() -> dict[str, Any]:
    return {
        "dependency_audit_available": shutil.which("cargo-audit") is not None,
        "dependency_audit_config_present": (ROOT / ".cargo-deny.toml").is_file(),
        "security_workflow_present": (ROOT / ".github/workflows/security.yml").is_file(),
    }


def _run_dependency_audit(
    source_revision: str | None,
    source_tree_clean: bool,
    run_id: str | None,
) -> dict[str, Any]:
    command = ["cargo", "audit", "--locked"]
    evidence: dict[str, Any] = {
        "command": command,
        "result": "HOLD",
        "exit_code": None,
        "output_sha256": None,
        "source_revision": source_revision,
        "source_tree_clean": source_tree_clean,
        "run_id": run_id,
    }
    if shutil.which("cargo-audit") is None:
        evidence["finding"] = "cargo-audit is not installed"
        return evidence
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        evidence["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
        evidence["result"] = "INCONCLUSIVE"
        evidence["finding"] = "cargo audit exceeded 300 seconds"
        return evidence
    except OSError as error:
        evidence["result"] = "INCONCLUSIVE"
        evidence["finding"] = f"cargo audit could not run: {error}"
        return evidence
    output = completed.stdout + completed.stderr
    evidence["exit_code"] = completed.returncode
    evidence["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    if completed.returncode == 0:
        evidence["result"] = "PASS"
        evidence["finding"] = "cargo audit completed successfully"
    elif re.search(
        r"\berror:\s*\d+\s+vulnerabilit(?:y|ies)\s+found\b",
        output,
        re.IGNORECASE,
    ):
        evidence["result"] = "FAIL"
        evidence["finding"] = "cargo audit reported known vulnerabilities"
    else:
        evidence["result"] = "INCONCLUSIVE"
        evidence["finding"] = f"cargo audit exited with {completed.returncode}"
    return evidence


def _read_artifact_text(path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, "missing"
    return _read_text(path)


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


def _workspace_manifest_inventory() -> tuple[list[dict[str, str]] | None, str | None]:
    completed = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None, completed.stderr.strip() or "cargo metadata failed"
    try:
        metadata = json.loads(completed.stdout)
        members = set(metadata["workspace_members"])
        inventory = []
        for package in metadata["packages"]:
            if package["id"] not in members:
                continue
            manifest = Path(package["manifest_path"]).resolve()
            inventory.append(
                {
                    "name": package["name"],
                    "manifest_path": manifest.relative_to(ROOT.resolve()).as_posix(),
                }
            )
        return sorted(inventory, key=lambda item: item["name"]), None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        return None, f"Could not parse Cargo workspace inventory: {error}"


def _workspace_dependency_graph() -> tuple[list[str] | None, list[tuple[str, str]] | None, str | None]:
    completed = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None, None, completed.stderr.strip() or "cargo metadata failed"
    try:
        metadata = json.loads(completed.stdout)
        members = set(metadata["workspace_members"])
        packages = [package for package in metadata["packages"] if package["id"] in members]
        package_by_path = {
            str(Path(package["manifest_path"]).parent.resolve()): package["name"]
            for package in packages
        }
        edges: set[tuple[str, str]] = set()
        for package in packages:
            for dependency in package["dependencies"]:
                dependency_path = dependency.get("path")
                if dependency_path is None:
                    continue
                dependency_name = package_by_path.get(str(Path(dependency_path).resolve()))
                if dependency_name is None:
                    return (
                        None,
                        None,
                        f"Local dependency {dependency['name']} of {package['name']} is outside workspace inventory.",
                    )
                edges.add((package["name"], dependency_name))
        return sorted(package["name"] for package in packages), sorted(edges), None
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        return None, None, f"Could not parse cargo metadata: {error}"


def _run_g4_contract_tests() -> tuple[str | None, int | None, str | None]:
    try:
        completed = subprocess.run(
            ["cargo", "test", "--locked", "-p", "palaco-runtime", "-p", "palaco-kernel"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as error:
        return None, None, str(error)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return output, None, "Runtime/kernel contract tests exceeded 180 seconds."
    output = completed.stdout + completed.stderr
    return output, completed.returncode, None


def _run_g5_contract_tests() -> tuple[str | None, int | None, str | None]:
    try:
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "palaco-eventbus",
                "-p",
                "palaco-rio-core",
                "-p",
                "palaco-observatory",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as error:
        return None, None, str(error)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return output, None, "Event/observability contract tests exceeded 180 seconds."
    output = completed.stdout + completed.stderr
    return output, completed.returncode, None


def _run_g7_integration_tests() -> tuple[str | None, int | None, str | None]:
    try:
        completed = subprocess.run(
            ["cargo", "test", "--locked", "--workspace"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError as error:
        return None, None, str(error)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return output, None, "Integrated workspace tests exceeded 300 seconds."
    output = completed.stdout + completed.stderr
    return output, completed.returncode, None


def _artifact(path: Path) -> dict[str, str] | None:
    try:
        if not path.is_file():
            return None
        return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)}
    except (OSError, RuntimeError, ValueError):
        return {"path": str(path), "sha256": "unavailable"}


def _artifact_in_directory(path: Path, directory: Path) -> dict[str, str] | None:
    try:
        if not path.is_file():
            return None
        relative_path = path.resolve().relative_to(directory.resolve()).as_posix()
        return {"path": relative_path, "sha256": digest(path)}
    except (OSError, RuntimeError, ValueError):
        return None


def _resolve_release_evidence_dir(path: Path) -> tuple[Path | None, str | None]:
    try:
        evidence_root = path.resolve(strict=True)
        repository_root = ROOT.resolve(strict=True)
        if not evidence_root.is_dir():
            return None, "release evidence path is not a directory"
        if evidence_root != repository_root:
            try:
                repository_root.relative_to(evidence_root)
            except ValueError:
                pass
            else:
                return None, "release evidence directory must not contain the repository root"
        return evidence_root, None
    except (OSError, RuntimeError) as error:
        return None, f"release evidence directory could not be resolved: {error}"


def build_report(
    scope_path: Path,
    graph_path: Path,
    output_dir: Path,
    release_evidence_dir: Path = ROOT,
) -> dict[str, Any]:
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
    ordering, ordering_error = read_json(ORDERING_PATH)
    if not ORDERING_PATH.is_file():
        ordering_error = "missing"
    dependency_nodes, dependency_edges, dependency_error = _workspace_dependency_graph()
    if dependency_error:
        g2, dependency_graph = evaluate_g2(None, None, ordering, ordering_error)
        g2["findings"] = [f"Cargo dependency inventory is unavailable: {dependency_error}"]
    else:
        g2, dependency_graph = evaluate_g2(
            dependency_nodes,
            dependency_edges,
            ordering if ordering_error is None else None,
            ordering_error,
        )
    plan, plan_error = read_json(PLAN_PATH)
    if not PLAN_PATH.is_file():
        plan_error = "missing"
    g3, execution_schedule = evaluate_g3(
        graph,
        plan,
        revision,
        g1["result"],
        g2["result"],
        plan_error,
    )
    g4_output, g4_exit_code, g4_error = _run_g4_contract_tests()
    g4, g4_evidence = evaluate_g4(
        g4_output,
        g4_exit_code,
        g3["result"],
        g4_error,
        revision or None,
        not dirty,
        os.environ.get("GITHUB_RUN_ID"),
    )
    g5_output, g5_exit_code, g5_error = _run_g5_contract_tests()
    g5, g5_evidence = evaluate_g5(
        g5_output,
        g5_exit_code,
        g4["result"],
        g5_error,
        revision or None,
        not dirty,
        os.environ.get("GITHUB_RUN_ID"),
    )
    workspace_inventory, inventory_error = _workspace_manifest_inventory()
    g6, architecture_compliance = evaluate_g6(
        graph,
        graph_error,
        workspace_inventory,
        inventory_error,
        [gate["result"] for gate in (g0, g1, g2, g3, g4, g5)],
        revision or None,
    )
    scope_artifact = _artifact(scope_path)
    graph_artifact = _artifact(graph_path)
    g7_output, g7_exit_code, g7_error = _run_g7_integration_tests()
    g7, integrated_validation = evaluate_g7(
        g7_output,
        g7_exit_code,
        [g0, g1, g2, g3, g4, g5, g6],
        revision or None,
        not dirty,
        _repository_identity(),
        scope if isinstance(scope, dict) else None,
        scope_artifact,
        g4_evidence,
        g5_evidence,
        {
            **architecture_compliance,
            "system_graph_artifact_sha256": graph_artifact.get("sha256") if graph_artifact else None,
        },
        graph_artifact,
        dependency_graph,
        execution_schedule,
        g7_error,
        os.environ.get("GITHUB_RUN_ID"),
    )
    checklist_text, checklist_error = _read_artifact_text(G8_CHECKLIST_PATH)
    threat_model_text, threat_model_error = _read_artifact_text(G8_THREAT_MODEL_PATH)
    checklist_artifact = _artifact(G8_CHECKLIST_PATH)
    threat_model_artifact = _artifact(G8_THREAT_MODEL_PATH)
    dependency_audit = _run_dependency_audit(
        revision or None,
        not dirty,
        os.environ.get("GITHUB_RUN_ID"),
    )
    g8, security_validation = evaluate_g8(
        checklist_text,
        threat_model_text,
        checklist_error,
        threat_model_error,
        revision or None,
        not dirty,
        checklist_artifact,
        threat_model_artifact,
        [g0, g1, g2, g3, g4, g5, g6, g7],
        _security_environment(),
        dependency_audit,
    )
    resolved_release_evidence_dir, release_root_error = _resolve_release_evidence_dir(
        release_evidence_dir
    )
    release_evidence_dir = resolved_release_evidence_dir or ROOT.resolve()
    release_checklist_path = (
        G9_RELEASE_PATH
        if release_evidence_dir == ROOT.resolve()
        else release_evidence_dir / "validation/release_validation.md"
    )
    if release_root_error:
        release_text, release_error = None, release_root_error
    else:
        try:
            checklist_exists = release_checklist_path.is_file()
        except (OSError, RuntimeError, ValueError) as error:
            release_text, release_error = None, f"release checklist could not be inspected: {error}"
        else:
            if not checklist_exists:
                release_text, release_error = None, "missing"
            else:
                try:
                    release_checklist_path.resolve().relative_to(release_evidence_dir)
                except (OSError, RuntimeError, ValueError) as error:
                    release_text, release_error = None, f"release checklist path is invalid: {error}"
                else:
                    release_text, release_error = _read_artifact_text(release_checklist_path)
    if release_evidence_dir == ROOT.resolve():
        release_artifact = _artifact(release_checklist_path)
    else:
        release_artifact = _artifact_in_directory(release_checklist_path, release_evidence_dir)
    g9, release_validation = evaluate_g9(
        release_text,
        release_error,
        revision or None,
        _repository_identity(),
        not dirty,
        [g0, g1, g2, g3, g4, g5, g6, g7, g8],
        release_artifact,
        release_evidence_dir,
    )

    report: dict[str, Any] = {
        "format_version": 1,
        "validator": {"name": "PVC-001 G0-G9 validator", "version": VALIDATOR_VERSION},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": _repository_identity(),
        "revision": revision or None,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "artifacts": {
            "scope": _artifact(scope_path),
            "system_graph": _artifact(graph_path),
            "system_graph_schema": _artifact(GRAPH_SCHEMA_PATH),
            "dependency_ordering": _artifact(ORDERING_PATH),
            "execution_plan": _artifact(PLAN_PATH),
            "execution_plan_schema": _artifact(PLAN_SCHEMA_PATH),
        },
        "dependency_graph": dependency_graph,
        "execution_schedule": execution_schedule,
        "runtime_kernel_tests": g4_evidence,
        "event_observability_tests": g5_evidence,
        "architecture_compliance": architecture_compliance,
        "integrated_validation": integrated_validation,
        "security_validation": security_validation,
        "release_validation": release_validation,
        "gates": [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "pvc-001-evidence.json"
    markdown_path = output_dir / "pvc-001-evidence.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return report


def render_markdown(report: dict[str, Any]) -> str:
    dependency_sha256 = report["dependency_graph"].get("sha256") or "unavailable"
    plan_sha256 = report["execution_schedule"].get("plan_sha256") or "unavailable"
    lines = [
        "# PVC-001 G0-G9 Evidence",
        "",
        f"- Repository: `{report['repository'] or 'unknown'}`",
        f"- Revision: `{report['revision'] or 'unknown'}`",
        f"- Validator: `{report['validator']['name']} {report['validator']['version']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Cargo dependency graph SHA-256: `{dependency_sha256}`",
        f"- ExecutionPlan SHA-256: `{plan_sha256}`",
        "",
        "| Gate | Result | Findings |",
        "|---|---|---|",
    ]
    for gate in report["gates"]:
        findings = "; ".join(gate["findings"]).replace("|", "\\|")
        lines.append(f"| {gate['gate']} | **{gate['result']}** | {findings} |")
    runtime_tests = report["runtime_kernel_tests"]
    lines.extend(
        [
            "",
            "## Runtime/kernel contract test evidence",
            "",
            f"- Command: `{' '.join(runtime_tests['command'])}`",
            f"- Source revision: `{runtime_tests['source_revision'] or 'unavailable'}`",
            f"- Source tree clean: `{runtime_tests['source_tree_clean']}`",
            f"- CI run ID: `{runtime_tests['run_id'] or 'unavailable'}`",
            f"- Exit code: `{runtime_tests['exit_code']}`",
            f"- Output SHA-256: `{runtime_tests['output_sha256'] or 'unavailable'}`",
            "",
            "| Scenario | Result |",
            "|---|---|",
        ]
    )
    lines.extend(
        f"| `{scenario['name']}` | {scenario['result']} |"
        for scenario in runtime_tests["scenarios"]
    )
    event_tests = report["event_observability_tests"]
    lines.extend(
        [
            "",
            "## Event/observability contract test evidence",
            "",
            f"- Command: `{' '.join(event_tests['command'])}`",
            f"- Source revision: `{event_tests['source_revision'] or 'unavailable'}`",
            f"- Source tree clean: `{event_tests['source_tree_clean']}`",
            f"- CI run ID: `{event_tests['run_id'] or 'unavailable'}`",
            f"- Exit code: `{event_tests['exit_code']}`",
            f"- Output SHA-256: `{event_tests['output_sha256'] or 'unavailable'}`",
            "",
            "| Scenario | Result |",
            "|---|---|",
        ]
    )
    lines.extend(
        f"| `{scenario['name']}` | {scenario['result']} |"
        for scenario in event_tests["scenarios"]
    )
    compliance = report["architecture_compliance"]
    lines.extend(
        [
            "",
            "## Architecture compliance",
            "",
            f"- Ruleset: `{compliance['ruleset_version']}`",
            f"- Implementation revision: `{compliance['source_revision'] or 'unavailable'}`",
            f"- SystemGraph revision: `{compliance['system_graph_revision'] or 'unavailable'}`",
            f"- SystemGraph SHA-256: `{compliance['system_graph_sha256'] or 'unavailable'}`",
            f"- Implementation inventory SHA-256: `{compliance['inventory_sha256'] or 'unavailable'}`",
            "",
            "| Component | Manifest |",
            "|---|---|",
        ]
    )
    lines.extend(
        f"| `{package['name']}` | `{package['manifest_path']}` |"
        for package in compliance["inventory"] or []
    )
    if compliance["classifications"]:
        lines.extend(["", "| Classification | Rule | Result | Detail |", "|---|---|---|---|"])
        for item in compliance["classifications"]:
            detail = item.get("detail", "").replace("|", "\\|")
            lines.append(f"| {item['class']} | {item['rule']} | {item['result']} | {detail} |")
    integration = report["integrated_validation"]
    lines.extend(
        [
            "",
            "## Integrated validation",
            "",
            f"- Command: `{' '.join(integration['command'])}`",
            f"- Repository: `{integration['repository'] or 'unavailable'}`",
            f"- Scope: `{integration['scope'] or 'unavailable'}`",
            f"- Scope SHA-256: `{integration['scope_sha256'] or 'unavailable'}`",
            f"- Source revision: `{integration['source_revision'] or 'unavailable'}`",
            f"- Source tree clean: `{integration['source_tree_clean']}`",
            f"- CI run ID: `{integration['run_id'] or 'unavailable'}`",
            f"- Exit code: `{integration['exit_code']}`",
            f"- Output SHA-256: `{integration['output_sha256'] or 'unavailable'}`",
            "",
            "| Scenario | Result |",
            "|---|---|",
        ]
    )
    lines.extend(
        f"| `{scenario['name']}` | {scenario['result']} |"
        for scenario in integration["scenarios"]
    )
    lines.extend(["", "| Reconciled gate | Result |", "|---|---|"])
    lines.extend(
        f"| {gate['gate']} | {gate['result']} |"
        for gate in integration["reconciled_gates"]
    )
    if integration["reconciliation"]:
        lines.extend(["", "| Evidence item | Observed | Expected |", "|---|---|---|"])
        lines.extend(
            f"| {item['item']} | `{item['observed'] or 'unavailable'}` | "
            f"`{item['expected'] or 'unavailable'}` |"
            for item in integration["reconciliation"]
        )
    security = report["security_validation"]
    environment = security["security_environment"]
    lines.extend(
        [
            "",
            "## Security validation",
            "",
            f"- Source revision: `{security['source_revision'] or 'unavailable'}`",
            f"- Source tree clean: `{security['source_tree_clean']}`",
            f"- Checklist: `{security['checklist']['path'] if security['checklist'] else 'unavailable'}`",
            f"- Checklist SHA-256: `{security['checklist']['sha256'] if security['checklist'] else 'unavailable'}`",
            f"- Threat model: `{security['threat_model']['path'] if security['threat_model'] else 'unavailable'}`",
            f"- Threat-model SHA-256: `{security['threat_model']['sha256'] if security['threat_model'] else 'unavailable'}`",
            f"- Cargo audit available: `{environment['dependency_audit_available']}`",
            f"- Supply-chain config present: `{environment['dependency_audit_config_present']}`",
            f"- Dedicated security workflow present: `{environment['security_workflow_present']}`",
            f"- Dependency audit: `{security['dependency_audit']['result']}`",
            f"- Dependency audit command: `{' '.join(security['dependency_audit']['command'])}`",
            f"- Dependency audit exit code: `{security['dependency_audit']['exit_code']}`",
            f"- Dependency audit output SHA-256: `{security['dependency_audit']['output_sha256'] or 'unavailable'}`",
            "",
            "| Control | Status | Evidence | Verified digest |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| {control['control']} | {control['status']} | `{control['evidence']}` | "
        f"{control.get('observed_sha256', 'unverified')} |"
        for control in security["controls"]
    )
    release = report["release_validation"]
    lines.extend(
        [
            "",
            "## Release validation",
            "",
            f"- Source revision: `{release['source_revision'] or 'unavailable'}`",
            f"- Source tree clean: `{release['source_tree_clean']}`",
            f"- Evidence root: `{release['evidence_root']}`",
            f"- Release checklist: `{release['release_checklist']['path'] if release['release_checklist'] else 'unavailable'}`",
            f"- Release checklist SHA-256: `{release['release_checklist']['sha256'] if release['release_checklist'] else 'unavailable'}`",
            f"- Release artifact: `{release['artifact']['path'] if release['artifact'] else 'unavailable'}`",
            f"- Artifact SHA-256: `{release['artifact']['sha256'] if release['artifact'] else 'unavailable'}`",
            f"- G0-G8 evidence report: `{release['evidence_report']['path'] if release['evidence_report'] else 'unavailable'}`",
            f"- Referenced report G9 result (not a prerequisite): `{release['evidence_report_g9_result'] or 'not present'}`",
            f"- Attestation: `{release['attestation']['path'] if release['attestation'] else 'unavailable'}`",
            f"- Decision authority: `{release['decision_authority'] or 'unavailable'}`",
            f"- Decision record: `{release['decision_record'] or 'unavailable'}`",
            f"- Recorded decision: `{release['decision'] or 'unavailable'}`",
            f"- Technically release eligible: `{release['release_eligible']}`",
            f"- Attestation binds source/artifact/evidence: `{release['attestation_binding_verified']}`",
            "- Attestation signature/authenticity verified: `not performed`",
            f"- Approval claimed: `{release['release_approval_claimed']}`",
            "- Decision-authority authentication: `not performed`",
        ]
    )
    layers = report["execution_schedule"].get("execution_layers", [])
    lines.extend(["", "## Deterministic execution layers", ""])
    if layers:
        lines.extend(
            f"{index}. " + ", ".join(f"`{step}`" for step in layer)
            for index, layer in enumerate(layers, 1)
        )
    else:
        lines.append("Unavailable until a valid, revision-bound ExecutionPlan is supplied.")
    lines.extend(["", "This report records validation evidence only; it grants no authority."])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, default=SCOPE_PATH)
    parser.add_argument("--graph", type=Path, default=GRAPH_PATH)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--release-evidence-dir",
        type=Path,
        help="directory containing validation/release_validation.md and the referenced release evidence files",
    )
    args = parser.parse_args()

    report = build_report(
        args.scope.resolve(),
        args.graph.resolve(),
        args.output_dir.resolve(),
        args.release_evidence_dir if args.release_evidence_dir else ROOT,
    )
    for gate in report["gates"]:
        print(f"{gate['gate']}: {gate['result']}")
        for finding in gate["findings"]:
            print(f"  - {finding}")
    return 1 if any(gate["result"] == "FAIL" for gate in report["gates"]) else 0


if __name__ == "__main__":
    sys.exit(main())
