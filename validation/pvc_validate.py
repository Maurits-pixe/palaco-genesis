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
ORDERING_PATH = ROOT / "validation/dependency-ordering.json"
PLAN_PATH = ROOT / "validation/execution-plan.json"
PLAN_SCHEMA_PATH = ROOT / "validation/execution-plan.schema.json"
VALIDATOR_VERSION = "0.6.0"
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

    report: dict[str, Any] = {
        "format_version": 1,
        "validator": {"name": "PVC-001 G0-G5 validator", "version": VALIDATOR_VERSION},
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
        "gates": [g0, g1, g2, g3, g4, g5],
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
        "# PVC-001 G0-G5 Evidence",
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
    args = parser.parse_args()

    report = build_report(args.scope.resolve(), args.graph.resolve(), args.output_dir.resolve())
    for gate in report["gates"]:
        print(f"{gate['gate']}: {gate['result']}")
        for finding in gate["findings"]:
            print(f"  - {finding}")
    return 1 if any(gate["result"] == "FAIL" for gate in report["gates"]) else 0


if __name__ == "__main__":
    sys.exit(main())
