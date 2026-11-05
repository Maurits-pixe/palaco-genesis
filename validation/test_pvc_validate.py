import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from pvc_validate import (
    G4_SCENARIOS,
    G5_SCENARIOS,
    G7_SCENARIOS,
    G8_REQUIRED_CONTROLS,
    VALIDATOR_VERSION,
    _artifact_in_directory,
    _canonical_sha256,
    _dependency_graph_digest,
    _ordering_approval_digest,
    _repository_identity,
    _resolve_release_evidence_dir,
    _run_dependency_audit,
    digest,
    evaluate_g0,
    evaluate_g1,
    evaluate_g2,
    evaluate_g3,
    evaluate_g4,
    evaluate_g5,
    evaluate_g6,
    evaluate_g7,
    evaluate_g8,
    evaluate_g9,
)


class G0Tests(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "schema_version": 1,
            "scope": "PALACO Core Alpha",
            "repository": "Maurits-pixe/palaco-genesis",
            "required_components": ["palaco-foundation"],
            "excluded_paths": [],
        }

    def test_passes_for_bound_repository_revision_and_inventory(self):
        result = evaluate_g0(
            self.scope,
            "Maurits-pixe/palaco-genesis",
            "abc123",
            {"palaco-foundation"},
            False,
        )
        self.assertEqual(result["result"], "PASS")

    def test_fails_when_workspace_inventory_changes(self):
        result = evaluate_g0(
            self.scope,
            "Maurits-pixe/palaco-genesis",
            "abc123",
            {"palaco-foundation", "palaco-runtime"},
            False,
        )
        self.assertEqual(result["result"], "FAIL")

    def test_dirty_source_is_inconclusive(self):
        result = evaluate_g0(
            self.scope,
            "Maurits-pixe/palaco-genesis",
            "abc123",
            {"palaco-foundation"},
            True,
        )
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_missing_repository_identity_is_hold(self):
        result = evaluate_g0(self.scope, None, "abc123", {"palaco-foundation"}, False)
        self.assertEqual(result["result"], "HOLD")

    def test_invalid_scope_version_fails(self):
        scope = {**self.scope, "schema_version": 2}
        result = evaluate_g0(scope, "Maurits-pixe/palaco-genesis", "abc123", {"palaco-foundation"}, False)
        self.assertEqual(result["result"], "FAIL")

    def test_github_repository_identity_is_normalized(self):
        with patch.dict("os.environ", {"GITHUB_REPOSITORY": "Maurits-pixe/palaco-genesis"}):
            self.assertEqual(_repository_identity(), "Maurits-pixe/palaco-genesis")


class G1Tests(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "required_graph_nodes": ["foundation", "runtime"],
            "required_graph_relations": [
                {"source": "foundation", "target": "runtime", "kind": "supports"}
            ],
            "graph_inventory_approval": {
                "status": "approved",
                "graph_revision": "abc123",
                "approved_by": "reviewer",
                "decision_ref": "decision-1",
            },
        }
        self.graph = {
            "schema_version": 1,
            "revision": "abc123",
            "nodes": [
                {"id": "foundation", "kind": "capability", "source_paths": ["crates/palaco-foundation"]},
                {"id": "runtime", "kind": "service", "source_paths": ["crates/palaco-runtime"]},
            ],
            "relation_kinds": {
                "supports": {
                    "meaning": "declares a supported runtime capability",
                    "source_kinds": ["capability"],
                    "target_kinds": ["service"],
                }
            },
            "relations": [{"source": "foundation", "target": "runtime", "kind": "supports"}],
        }

    def test_missing_graph_is_hold(self):
        result = evaluate_g1(None, self.scope, "abc123", "missing")
        self.assertEqual(result["result"], "HOLD")

    def test_missing_approved_inventory_is_hold(self):
        result = evaluate_g1(self.graph, {}, "abc123")
        self.assertEqual(result["result"], "HOLD")

    def test_inventory_without_approval_is_hold(self):
        scope = {**self.scope, "graph_inventory_approval": {"status": "unapproved"}}
        result = evaluate_g1(self.graph, scope, "abc123")
        self.assertEqual(result["result"], "HOLD")

    def test_approval_must_bind_graph_revision(self):
        self.scope["graph_inventory_approval"]["graph_revision"] = "approved-v2"
        result = evaluate_g1(self.graph, self.scope, "abc123")
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_valid_graph_passes_for_bound_revision(self):
        result = evaluate_g1(self.graph, self.scope, "abc123")
        self.assertEqual(result["result"], "PASS")

    def test_revision_mismatch_is_inconclusive(self):
        result = evaluate_g1(self.graph, self.scope, "different")
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_unknown_relation_endpoint_fails(self):
        self.graph["relations"][0]["target"] = "unknown"
        result = evaluate_g1(self.graph, self.scope, "abc123")
        self.assertEqual(result["result"], "FAIL")

    def test_unsupported_relation_endpoint_kind_fails(self):
        self.graph["nodes"][0]["kind"] = "resource"
        result = evaluate_g1(self.graph, self.scope, "abc123")
        self.assertEqual(result["result"], "FAIL")

    def test_source_path_traversal_fails(self):
        self.graph["nodes"][0]["source_paths"] = ["../../etc/passwd"]
        result = evaluate_g1(self.graph, self.scope, "abc123")
        self.assertEqual(result["result"], "FAIL")

    def test_invalid_graph_fails_even_without_approved_inventory(self):
        self.graph["relations"][0]["target"] = "unknown"
        result = evaluate_g1(self.graph, {}, "abc123")
        self.assertEqual(result["result"], "FAIL")


class G2Tests(unittest.TestCase):
    def setUp(self):
        self.nodes = ["foundation", "runtime", "kernel"]
        self.edges = [("runtime", "foundation"), ("kernel", "runtime")]
        self.ordering = {
            "schema_version": 1,
            "status": "unapproved",
            "graph_sha256": None,
            "approval_sha256": None,
            "startup_constraints": None,
            "shutdown_constraints": None,
            "approved_by": None,
            "decision_ref": None,
        }

    def test_dependency_graph_is_checked_but_unapproved_ordering_holds(self):
        result, graph = evaluate_g2(self.nodes, self.edges, self.ordering)
        self.assertEqual(result["result"], "HOLD")
        self.assertEqual(graph["topological_order"], ["foundation", "runtime", "kernel"])
        graph_without_digest = {key: value for key, value in graph.items() if key != "sha256"}
        self.assertEqual(graph["sha256"], _dependency_graph_digest(graph_without_digest))

    def test_missing_ordering_evidence_is_hold(self):
        result, _ = evaluate_g2(self.nodes, self.edges, None, "missing")
        self.assertEqual(result["result"], "HOLD")

    def test_dependency_cycle_fails(self):
        result, _ = evaluate_g2(
            self.nodes,
            self.edges + [("foundation", "kernel")],
            self.ordering,
        )
        self.assertEqual(result["result"], "FAIL")
        self.assertTrue(any("cycle" in finding.lower() for finding in result["findings"]))

    def test_unknown_dependency_node_fails(self):
        result, _ = evaluate_g2(self.nodes, self.edges + [("runtime", "missing")], self.ordering)
        self.assertEqual(result["result"], "FAIL")

    def test_startup_order_cycle_fails(self):
        ordering = {
            **self.ordering,
            "startup_constraints": [
                {"before": "foundation", "after": "runtime"},
                {"before": "runtime", "after": "foundation"},
            ],
            "shutdown_constraints": [],
        }
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "FAIL")

    def test_startup_order_is_interpreted_before_then_after(self):
        ordering = {
            **self.ordering,
            "startup_constraints": [{"before": "foundation", "after": "runtime"}],
            "shutdown_constraints": [],
        }
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "HOLD")
        ordering["startup_constraints"] = [{"before": "runtime", "after": "foundation"}]
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "FAIL")

    def test_approved_constraints_must_bind_dependency_graph_digest(self):
        _, graph = evaluate_g2(self.nodes, self.edges, self.ordering)
        ordering = {
            **self.ordering,
            "status": "approved",
            "graph_sha256": graph["sha256"],
            "startup_constraints": [],
            "shutdown_constraints": [],
            "approved_by": "reviewer",
            "decision_ref": "decision-2",
        }
        ordering["approval_sha256"] = _ordering_approval_digest(
            ordering["graph_sha256"],
            ordering["startup_constraints"],
            ordering["shutdown_constraints"],
            ordering["approved_by"],
            ordering["decision_ref"],
        )
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "PASS")

    def test_changed_constraints_invalidate_approval_digest(self):
        _, graph = evaluate_g2(self.nodes, self.edges, self.ordering)
        startup = [{"before": "foundation", "after": "runtime"}]
        shutdown = [{"before": "runtime", "after": "foundation"}]
        ordering = {
            **self.ordering,
            "status": "approved",
            "graph_sha256": graph["sha256"],
            "startup_constraints": startup,
            "shutdown_constraints": shutdown,
            "approved_by": "reviewer",
            "decision_ref": "decision-2",
            "approval_sha256": _ordering_approval_digest(
                graph["sha256"], startup, shutdown, "reviewer", "decision-2"
            ),
        }
        ordering["startup_constraints"] = []
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "HOLD")

    def test_changed_approval_identity_invalidates_approval_digest(self):
        _, graph = evaluate_g2(self.nodes, self.edges, self.ordering)
        ordering = {
            **self.ordering,
            "status": "approved",
            "graph_sha256": graph["sha256"],
            "startup_constraints": [],
            "shutdown_constraints": [],
            "approved_by": "reviewer",
            "decision_ref": "decision-2",
        }
        ordering["approval_sha256"] = _ordering_approval_digest(
            graph["sha256"], [], [], ordering["approved_by"], ordering["decision_ref"]
        )
        ordering["decision_ref"] = "decision-3"
        result, _ = evaluate_g2(self.nodes, self.edges, ordering)
        self.assertEqual(result["result"], "HOLD")


class G3Tests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "schema_version": 1,
            "revision": "abc123",
            "nodes": [
                {"id": "foundation", "kind": "service", "source_paths": ["crates/palaco-foundation"]},
                {"id": "runtime", "kind": "service", "source_paths": ["crates/palaco-runtime"]},
                {"id": "capability", "kind": "capability", "source_paths": ["crates/palaco-types"]},
            ],
            "relation_kinds": {
                "depends_on": {
                    "meaning": "requires successful startup of target before source",
                    "source_kinds": ["service"],
                    "target_kinds": ["service"],
                }
            },
            "relations": [
                {"source": "runtime", "target": "foundation", "kind": "depends_on"}
            ],
        }
        self.plan = {
            "schema_version": 1,
            "source_revision": "abc123",
            "system_graph_sha256": _canonical_sha256(self.graph),
            "planner": {"name": "test-planner", "version": "1"},
            "dependency_relation_kinds": ["depends_on"],
            "steps": [
                {
                    "id": "foundation-start",
                    "graph_node": "foundation",
                    "depends_on": [],
                    "recovery_point": "restore foundation snapshot",
                },
                {
                    "id": "runtime-start",
                    "graph_node": "runtime",
                    "depends_on": ["foundation-start"],
                    "recovery_point": "restore runtime snapshot",
                },
            ],
        }

    def evaluate(self, plan=None, graph=None, g1="PASS", g2="PASS", revision="abc123", error=None):
        return evaluate_g3(
            self.graph if graph is None else graph,
            self.plan if plan is None else plan,
            revision,
            g1,
            g2,
            error,
        )

    def test_valid_plan_passes_and_emits_deterministic_parallel_layers(self):
        first_result, first_schedule = self.evaluate()
        second_result, second_schedule = self.evaluate()
        self.assertEqual(first_result["result"], "PASS")
        self.assertEqual(first_schedule, second_schedule)
        self.assertEqual(
            first_schedule["execution_layers"],
            [["foundation-start"], ["runtime-start"]],
        )

    def test_independent_steps_share_parallel_layer(self):
        graph = {**self.graph, "relations": []}
        plan = {
            **self.plan,
            "system_graph_sha256": _canonical_sha256(graph),
            "steps": [
                {**self.plan["steps"][0], "depends_on": []},
                {**self.plan["steps"][1], "depends_on": []},
            ],
        }
        result, schedule = self.evaluate(plan=plan, graph=graph)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(schedule["execution_layers"], [["foundation-start", "runtime-start"]])

    def test_missing_plan_is_hold(self):
        result, _ = self.evaluate(plan=None, error="missing")
        self.assertEqual(result["result"], "HOLD")

    def test_failed_prerequisites_hold_valid_plan(self):
        result, _ = self.evaluate(g1="HOLD")
        self.assertEqual(result["result"], "HOLD")

    def test_missing_service_is_failure(self):
        plan = {**self.plan, "steps": self.plan["steps"][:1]}
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "FAIL")

    def test_dependency_mismatch_is_failure(self):
        plan = {**self.plan, "steps": [{**self.plan["steps"][0]}, {**self.plan["steps"][1], "depends_on": []}]}
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "FAIL")

    def test_plan_cycle_is_failure(self):
        plan = {
            **self.plan,
            "steps": [
                {**self.plan["steps"][0], "depends_on": ["runtime-start"]},
                {**self.plan["steps"][1], "depends_on": ["foundation-start"]},
            ],
        }
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "FAIL")

    def test_missing_recovery_point_is_failure(self):
        plan = {
            **self.plan,
            "steps": [{**self.plan["steps"][0], "recovery_point": ""}, self.plan["steps"][1]],
        }
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "FAIL")

    def test_plan_cannot_smuggle_authority_fields(self):
        plan = {**self.plan, "authorization": "approved"}
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "FAIL")

    def test_plan_revision_mismatch_is_inconclusive(self):
        result, _ = self.evaluate(revision="different")
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_graph_revision_mismatch_is_inconclusive(self):
        graph = {**self.graph, "revision": "stale"}
        plan = {**self.plan, "system_graph_sha256": _canonical_sha256(graph)}
        result, _ = self.evaluate(plan=plan, graph=graph)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_graph_digest_mismatch_is_inconclusive(self):
        plan = {**self.plan, "system_graph_sha256": "0" * 64}
        result, _ = self.evaluate(plan=plan)
        self.assertEqual(result["result"], "INCONCLUSIVE")


class G4Tests(unittest.TestCase):
    def setUp(self):
        self.scenarios = [
            "runtime_plan_confirms_execution_path",
            "runtime_plan_escalates_non_executable_scope",
            "runtime_plan_safe_state_fails_closed",
            "kernel_cycle_confirms_execution_path",
            "kernel_cycle_escalates_non_executable_scope",
            "kernel_cycle_safe_state_fails_closed",
        ]
        self.output = "".join(f"test tests::{name} ... ok\n" for name in self.scenarios)

    def test_passes_only_with_all_runtime_and_kernel_scenarios_and_g3(self):
        result, evidence = evaluate_g4(
            self.output, 0, "PASS", source_revision="abc123", source_tree_clean=True
        )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(evidence["scenarios"]), len(self.scenarios))
        self.assertEqual(evidence["source_revision"], "abc123")
        self.assertTrue(evidence["output_sha256"])

    def test_missing_scenario_is_hold(self):
        result, _ = evaluate_g4(
            self.output.replace("runtime_plan_safe_state_fails_closed", "omitted"),
            0,
            "PASS",
            source_revision="abc123",
            source_tree_clean=True,
        )
        self.assertEqual(result["result"], "HOLD")

    def test_failed_scenario_is_fail(self):
        output = self.output.replace("kernel_cycle_safe_state_fails_closed ... ok", "kernel_cycle_safe_state_fails_closed ... FAILED")
        result, _ = evaluate_g4(output, 101, "PASS", source_revision="abc123", source_tree_clean=True)
        self.assertEqual(result["result"], "FAIL")

    def test_passed_scenarios_hold_until_g3_passes(self):
        result, _ = evaluate_g4(
            self.output, 0, "HOLD", source_revision="abc123", source_tree_clean=True
        )
        self.assertEqual(result["result"], "HOLD")

    def test_unavailable_test_execution_is_hold(self):
        result, evidence = evaluate_g4(None, None, "PASS", "cargo is unavailable")
        self.assertEqual(result["result"], "HOLD")
        self.assertEqual(evidence["error"], "cargo is unavailable")

    def test_dirty_source_is_inconclusive(self):
        result, _ = evaluate_g4(
            self.output, 0, "PASS", source_revision="abc123", source_tree_clean=False
        )
        self.assertEqual(result["result"], "INCONCLUSIVE")


class G5Tests(unittest.TestCase):
    def setUp(self):
        self.scenarios = [
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
        ]
        event_tests = {
            "append_and_replay_reconstructs_the_complete_lifecycle",
            "revocation_survives_snapshot_replay",
            "missing_event_provenance_is_rejected_before_commit",
        }
        self.output = "".join(
            f"test {'event::tests' if name in event_tests else 'tests'}::{name} ... ok\n"
            for name in self.scenarios
        )

    def test_passes_with_all_scenarios_and_prior_gates(self):
        result, evidence = evaluate_g5(
            self.output,
            0,
            "PASS",
            source_revision="abc123",
            source_tree_clean=True,
        )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(evidence["scenarios"]), len(self.scenarios))
        self.assertTrue(evidence["output_sha256"])

    def test_missing_scenario_is_hold(self):
        output = self.output.replace("revocation_survives_snapshot_replay", "omitted")
        result, _ = evaluate_g5(
            output, 0, "PASS", source_revision="abc123", source_tree_clean=True
        )
        self.assertEqual(result["result"], "HOLD")

    def test_failed_scenario_is_fail(self):
        output = self.output.replace(
            "tests::action_flow_requires_authorization ... ok",
            "tests::action_flow_requires_authorization ... FAILED",
        )
        result, _ = evaluate_g5(
            output, 101, "PASS", source_revision="abc123", source_tree_clean=True
        )
        self.assertEqual(result["result"], "FAIL")

    def test_requires_g4_pass(self):
        result, _ = evaluate_g5(
            self.output, 0, "HOLD", source_revision="abc123", source_tree_clean=True
        )
        self.assertEqual(result["result"], "HOLD")

    def test_dirty_source_is_inconclusive(self):
        result, _ = evaluate_g5(
            self.output, 0, "PASS", source_revision="abc123", source_tree_clean=False
        )
        self.assertEqual(result["result"], "INCONCLUSIVE")


class G6Tests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "schema_version": 1,
            "revision": "abc123",
            "nodes": [
                {
                    "id": "foundation",
                    "kind": "service",
                    "source_paths": ["crates/palaco-foundation"],
                }
            ],
            "relation_kinds": {"supports": {"meaning": "support", "source_kinds": ["service"], "target_kinds": ["service"]}},
            "relations": [],
        }
        self.inventory = [
            {"name": "palaco-foundation", "manifest_path": "crates/palaco-foundation/Cargo.toml"}
        ]
        self.prior_results = ["PASS"] * 6

    def evaluate(self, graph=None, inventory=None, prior_results=None, revision="abc123", error=None):
        return evaluate_g6(
            self.graph if graph is None else graph,
            error,
            self.inventory if inventory is None else inventory,
            None,
            self.prior_results if prior_results is None else prior_results,
            revision,
        )

    def test_passes_when_graph_paths_cover_workspace_packages(self):
        result, evidence = self.evaluate()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(evidence["ruleset_version"], "1.0.0")
        self.assertTrue(evidence["inventory_sha256"])
        self.assertEqual(evidence["inventory"], self.inventory)

    def test_missing_graph_holds(self):
        result, _ = self.evaluate(graph=None, error="missing")
        self.assertEqual(result["result"], "HOLD")

    def test_missing_source_path_is_mandatory_violation(self):
        graph = {
            **self.graph,
            "nodes": [{**self.graph["nodes"][0], "source_paths": ["crates/missing-module"]}],
        }
        result, evidence = self.evaluate(graph=graph)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(evidence["classifications"][0]["class"], "mandatory_violation")

    def test_repository_root_is_not_a_valid_component_source_path(self):
        graph = {
            **self.graph,
            "nodes": [{**self.graph["nodes"][0], "source_paths": ["."]}],
        }
        result, _ = self.evaluate(graph=graph)
        self.assertEqual(result["result"], "FAIL")

    def test_uncovered_workspace_package_is_mandatory_violation(self):
        inventory = self.inventory + [
            {"name": "palaco-kernel", "manifest_path": "runtime/palaco-kernel/Cargo.toml"}
        ]
        result, evidence = self.evaluate(inventory=inventory)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(evidence["classifications"][0]["rule"], "G6-WORKSPACE-COVERAGE")

    def test_graph_revision_mismatch_is_inconclusive(self):
        graph = {**self.graph, "revision": "stale"}
        result, _ = self.evaluate(graph=graph)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_prior_gate_blocker_holds_compliance(self):
        result, _ = self.evaluate(prior_results=["PASS", "HOLD", "PASS", "PASS", "PASS", "PASS"])
        self.assertEqual(result["result"], "HOLD")

    def test_missing_prior_gate_results_hold_compliance(self):
        result, _ = self.evaluate(prior_results=[])
        self.assertEqual(result["result"], "HOLD")


class G7Tests(unittest.TestCase):
    def setUp(self):
        self.scenarios = [
            "runtime_plan_confirms_execution_path",
            "runtime_plan_escalates_non_executable_scope",
            "runtime_plan_safe_state_fails_closed",
            "kernel_cycle_confirms_execution_path",
            "kernel_cycle_escalates_non_executable_scope",
            "kernel_cycle_safe_state_fails_closed",
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
        ]
        self.output = "".join(
            f"test integration::tests::{name} ... ok\n" for name in self.scenarios
        )
        self.gates = [{"gate": f"G{index}", "result": "PASS"} for index in range(7)]
        self.g4 = {
            "source_revision": "abc123",
            "source_tree_clean": True,
            "run_id": "run-1",
        }
        self.g5 = {
            "source_revision": "abc123",
            "source_tree_clean": True,
            "run_id": "run-1",
        }
        self.g6 = {
            "source_revision": "abc123",
            "system_graph_revision": "abc123",
            "system_graph_artifact_sha256": "a" * 64,
            "inventory_sha256": "b" * 64,
        }
        self.graph_artifact = {"path": "validation/system-graph.json", "sha256": "a" * 64}
        self.scope_manifest = {
            "scope": "PALACO Core Alpha",
            "repository": "Maurits-pixe/palaco-genesis",
        }
        self.scope_artifact = {"path": "validation/core-alpha-scope.json", "sha256": "c" * 64}
        self.dependency_graph = {"sha256": "d" * 64}
        self.execution_schedule = {"plan_sha256": "e" * 64}

    def evaluate(self, **overrides):
        arguments = {
            "test_output": self.output,
            "exit_code": 0,
            "prior_gates": self.gates,
            "source_revision": "abc123",
            "source_tree_clean": True,
            "repository": "Maurits-pixe/palaco-genesis",
            "scope_manifest": self.scope_manifest,
            "scope_artifact": self.scope_artifact,
            "g4_evidence": self.g4,
            "g5_evidence": self.g5,
            "g6_evidence": self.g6,
            "system_graph_artifact": self.graph_artifact,
            "dependency_graph": self.dependency_graph,
            "execution_schedule": self.execution_schedule,
            "run_id": "run-1",
        }
        arguments.update(overrides)
        return evaluate_g7(**arguments)

    def test_passes_when_outputs_reconcile_and_integrated_scenarios_pass(self):
        result, evidence = self.evaluate()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(len(evidence["scenarios"]), len(self.scenarios))
        self.assertEqual(evidence["scope"], "PALACO Core Alpha")
        self.assertEqual(len(evidence["reconciliation"]), 5)

    def test_failed_integrated_test_is_fail(self):
        output = self.output.replace(
            "integration::tests::action_flow_requires_authorization ... ok",
            "integration::tests::action_flow_requires_authorization ... FAILED",
        )
        result, _ = self.evaluate(test_output=output, exit_code=101)
        self.assertEqual(result["result"], "FAIL")

    def test_missing_integrated_scenario_is_hold(self):
        result, _ = self.evaluate(test_output=self.output.replace("runtime_plan_safe_state_fails_closed", "omitted"))
        self.assertEqual(result["result"], "HOLD")

    def test_prior_fail_is_not_hidden_by_g7(self):
        gates = [*self.gates]
        gates[2] = {"gate": "G2", "result": "FAIL"}
        result, _ = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "FAIL")

    def test_prior_hold_blocks_g7(self):
        gates = [*self.gates]
        gates[1] = {"gate": "G1", "result": "HOLD"}
        result, _ = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "HOLD")

    def test_malformed_prior_gate_record_is_not_ignored(self):
        result, _ = self.evaluate(prior_gates=[*self.gates, None])
        self.assertEqual(result["result"], "HOLD")

    def test_conflicting_component_revision_is_inconclusive(self):
        g5 = {**self.g5, "source_revision": "different"}
        result, _ = self.evaluate(g5_evidence=g5)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_graph_digest_mismatch_is_inconclusive(self):
        graph_artifact = {**self.graph_artifact, "sha256": "f" * 64}
        result, _ = self.evaluate(system_graph_artifact=graph_artifact)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_scope_repository_mismatch_holds(self):
        scope_manifest = {**self.scope_manifest, "repository": "other/repository"}
        result, _ = self.evaluate(scope_manifest=scope_manifest)
        self.assertEqual(result["result"], "HOLD")

    def test_dirty_source_is_inconclusive(self):
        result, _ = self.evaluate(source_tree_clean=False)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_missing_ci_run_id_holds(self):
        result, _ = self.evaluate(run_id=None)
        self.assertEqual(result["result"], "HOLD")

    def test_graph_revision_mismatch_is_inconclusive(self):
        g6 = {**self.g6, "system_graph_revision": "stale"}
        result, _ = self.evaluate(g6_evidence=g6)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_conflicting_ci_run_ids_are_inconclusive(self):
        g4 = {**self.g4, "run_id": "different-run"}
        result, _ = self.evaluate(g4_evidence=g4)
        self.assertEqual(result["result"], "INCONCLUSIVE")


class G8Tests(unittest.TestCase):
    def setUp(self):
        self.controls = [
            "SEC-THREAT-MODEL",
            "SEC-SUPPLY-CHAIN",
            "SEC-SECRETS-CONFIG",
            "SEC-ADVERSARIAL",
            "SEC-INDEPENDENT-REVIEW",
        ]
        self.threat_model = (
            "# Threat model — Core Alpha\n\n"
            "Assets: authority, credentials.\n\n"
            "Trust boundaries: browser and server.\n\n"
            "Threats reviewed. No open risks remain.\n"
        )
        self.prior_gates = [{"gate": f"G{index}", "result": "PASS"} for index in range(8)]
        self.checklist_artifact = {"path": "validation/security_checklist.md", "sha256": "a" * 64}
        self.threat_artifact = {"path": "validation/threat-model.md", "sha256": "b" * 64}
        self.environment = {
            "dependency_audit_available": True,
            "dependency_audit_config_present": True,
            "security_workflow_present": True,
        }
        self.dependency_audit = {
            "result": "PASS",
            "source_revision": "abc123",
            "source_tree_clean": True,
            "output_sha256": "f" * 64,
        }

    def checklist(self, status="PASS", evidence=None):
        reference = evidence or f"Cargo.lock@{hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest()}"
        rows = "\n".join(f"| {control} | {status} | {reference} |" for control in self.controls)
        return f"**Scope:** PALACO Core Alpha\n\n| Control | Status | Evidence |\n|---|---|---|\n{rows}\n"

    def evaluate(self, **overrides):
        arguments = {
            "checklist_text": self.checklist(),
            "threat_model_text": self.threat_model,
            "checklist_error": None,
            "threat_model_error": None,
            "source_revision": "abc123",
            "source_tree_clean": True,
            "checklist_artifact": self.checklist_artifact,
            "threat_model_artifact": self.threat_artifact,
            "prior_gates": self.prior_gates,
            "security_environment": self.environment,
            "dependency_audit": self.dependency_audit,
        }
        arguments.update(overrides)
        return evaluate_g8(**arguments)

    def test_passes_only_with_complete_digest_bound_evidence(self):
        result, evidence = self.evaluate()
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(all(control["evidence_verified"] for control in evidence["controls"]))

    def test_open_control_holds(self):
        result, _ = self.evaluate(checklist_text=self.checklist(status="OPEN"))
        self.assertEqual(result["result"], "HOLD")

    def test_missing_checklist_holds(self):
        result, _ = self.evaluate(checklist_text=None, checklist_error="missing")
        self.assertEqual(result["result"], "HOLD")

    def test_missing_control_holds(self):
        checklist = self.checklist().replace("| SEC-ADVERSARIAL | PASS | Cargo.lock@" + hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest() + " |\n", "")
        result, _ = self.evaluate(checklist_text=checklist)
        self.assertEqual(result["result"], "HOLD")

    def test_invalid_status_fails(self):
        result, _ = self.evaluate(checklist_text=self.checklist(status="MAYBE"))
        self.assertEqual(result["result"], "FAIL")

    def test_evidence_digest_mismatch_fails(self):
        result, _ = self.evaluate(checklist_text=self.checklist(evidence=f"Cargo.lock@{'0' * 64}"))
        self.assertEqual(result["result"], "FAIL")

    def test_missing_evidence_artifact_holds(self):
        result, _ = self.evaluate(checklist_text=self.checklist(evidence=f"validation/missing.json@{'0' * 64}"))
        self.assertEqual(result["result"], "HOLD")

    def test_open_threat_model_holds(self):
        result, _ = self.evaluate(threat_model_text=self.threat_model + "OPEN: production blocked.\n")
        self.assertEqual(result["result"], "HOLD")

    def test_threat_model_without_core_alpha_scope_holds(self):
        result, _ = self.evaluate(threat_model_text=self.threat_model.replace("Core Alpha", "generic product"))
        self.assertEqual(result["result"], "HOLD")

    def test_prior_gate_hold_blocks_security_pass(self):
        gates = [*self.prior_gates]
        gates[6] = {"gate": "G6", "result": "HOLD"}
        result, _ = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "HOLD")

    def test_prior_gate_failure_is_not_hidden_by_open_controls(self):
        gates = [*self.prior_gates]
        gates[2] = {"gate": "G2", "result": "FAIL"}
        result, _ = self.evaluate(
            prior_gates=gates,
            checklist_text=self.checklist(status="OPEN"),
        )
        self.assertEqual(result["result"], "FAIL")

    def test_absent_dependency_audit_tool_holds(self):
        environment = {**self.environment, "dependency_audit_available": False}
        result, _ = self.evaluate(security_environment=environment)
        self.assertEqual(result["result"], "HOLD")

    def test_dependency_audit_must_pass_for_current_revision(self):
        audit = {**self.dependency_audit, "source_revision": "stale"}
        result, _ = self.evaluate(dependency_audit=audit)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_dependency_audit_failure_fails_gate(self):
        audit = {**self.dependency_audit, "result": "FAIL"}
        result, _ = self.evaluate(dependency_audit=audit)
        self.assertEqual(result["result"], "FAIL")

    @patch("pvc_validate.shutil.which", return_value="/usr/bin/cargo-audit")
    @patch(
        "pvc_validate.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["cargo", "audit", "--locked"], returncode=0, stdout="clean\n", stderr=""
        ),
    )
    def test_dependency_audit_runner_records_success_digest(self, _run, _which):
        evidence = _run_dependency_audit("abc123", True, "run-1")
        self.assertEqual(evidence["result"], "PASS")
        self.assertEqual(evidence["source_revision"], "abc123")
        self.assertTrue(evidence["output_sha256"])

    @patch("pvc_validate.shutil.which", return_value="/usr/bin/cargo-audit")
    @patch(
        "pvc_validate.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["cargo", "audit", "--locked"],
            returncode=1,
            stdout="error: 1 vulnerability found\n",
            stderr="",
        ),
    )
    def test_dependency_audit_runner_fails_on_reported_vulnerability(self, _run, _which):
        evidence = _run_dependency_audit("abc123", True, "run-1")
        self.assertEqual(evidence["result"], "FAIL")


class G9Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        patcher = patch("pvc_validate.ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.temp_dir.cleanup)
        self.source_revision = "a" * 40
        self.repository = "Maurits-pixe/palaco-genesis"
        self.prior_gates = [{"gate": f"G{index}", "result": "PASS"} for index in range(9)]
        (self.root / "dist").mkdir()
        (self.root / "validation").mkdir()
        (self.root / "dist/palaco.tar").write_bytes(b"release artifact")
        (self.root / "dist/attestation.json").write_text("{}\n", encoding="utf-8")
        self.report_path = self.root / "validation/prior-evidence.json"
        self.write_report()
        self.artifact = {"path": "validation/release_validation.md", "sha256": "a" * 64}

    def write_report(self, revision=None, gates=None):
        report_gates = gates or [
            *self.prior_gates,
            {"gate": "G9", "result": "HOLD"},
        ]
        for gate in report_gates:
            gate.setdefault("findings", [])
        report = {
            "format_version": 1,
            "validator": {"name": "PVC-001 G0-G9 validator", "version": VALIDATOR_VERSION},
            "generated_at": "2026-11-05T00:00:00+00:00",
            "repository": self.repository,
            "revision": revision or self.source_revision,
            "artifacts": {
                key: {"path": f"validation/{key}.json", "sha256": f"{index:064x}"}
                for index, key in enumerate(
                    (
                        "scope",
                        "system_graph",
                        "system_graph_schema",
                        "dependency_ordering",
                        "execution_plan",
                        "execution_plan_schema",
                    ),
                    1,
                )
            },
            "dependency_graph": {
                "dependency_scope": "workspace-local dependencies across normal, build, and dev kinds",
                "nodes": ["palaco-foundation"],
                "edges": [],
                "topological_order": ["palaco-foundation"],
            },
            "execution_schedule": {
                "execution_layers": [["service"]],
                "topological_order": ["service"],
                "plan_sha256": "2" * 64,
            },
            "architecture_compliance": {
                "source_revision": revision or self.source_revision,
                "system_graph_revision": revision or self.source_revision,
                "system_graph_sha256": "3" * 64,
            },
            "run_id": "run-1",
            "runtime_kernel_tests": {
                "run_id": "run-1",
                "source_revision": revision or self.source_revision,
                "source_tree_clean": True,
                "exit_code": 0,
                "output_sha256": "a" * 64,
                "scenarios": [
                    {"name": name, "result": "ok"} for name in sorted(G4_SCENARIOS)
                ],
            },
            "event_observability_tests": {
                "run_id": "run-1",
                "source_revision": revision or self.source_revision,
                "source_tree_clean": True,
                "exit_code": 0,
                "output_sha256": "b" * 64,
                "scenarios": [
                    {"name": name, "result": "ok"} for name in sorted(G5_SCENARIOS)
                ],
            },
            "integrated_validation": {
                "run_id": "run-1",
                "source_revision": revision or self.source_revision,
                "source_tree_clean": True,
                "repository": self.repository,
                "exit_code": 0,
                "output_sha256": "c" * 64,
                "scope_sha256": "1" * 64,
                "system_graph_artifact_sha256": "2" * 64,
                "dependency_graph_sha256": "4" * 64,
                "execution_plan_sha256": "2" * 64,
                "reconciliation": [
                    {"item": label, "observed": value, "expected": value}
                    for label, value in (
                        ("G4 source revision", revision or self.source_revision),
                        ("G5 source revision", revision or self.source_revision),
                        ("G6 source revision", revision or self.source_revision),
                        ("G6 graph revision", revision or self.source_revision),
                        ("G6 graph digest", "2" * 64),
                    )
                ],
                "scenarios": [
                    {"name": name, "result": "ok"} for name in sorted(G7_SCENARIOS)
                ],
            },
            "security_validation": {
                "source_revision": revision or self.source_revision,
                "source_tree_clean": True,
                "checklist": {"path": "validation/security_checklist.md", "sha256": "d" * 64},
                "threat_model": {"path": "release-registry/THREAT-MODEL.md", "sha256": "e" * 64},
                "security_environment": {
                    "dependency_audit_available": True,
                    "dependency_audit_config_present": True,
                    "security_workflow_present": True,
                },
                "dependency_audit": {
                    "result": "PASS",
                    "source_revision": revision or self.source_revision,
                    "source_tree_clean": True,
                    "run_id": "run-1",
                    "exit_code": 0,
                    "output_sha256": "f" * 64,
                },
                "controls": [
                    {
                        "control": control,
                        "status": "PASS",
                        "evidence": f"validation/{control}.json@{'1' * 64}",
                        "evidence_verified": True,
                        "observed_sha256": "1" * 64,
                    }
                    for control in sorted(G8_REQUIRED_CONTROLS)
                ],
            },
            "gates": report_gates,
        }
        report["dependency_graph"]["sha256"] = _dependency_graph_digest(
            report["dependency_graph"]
        )
        report["integrated_validation"]["dependency_graph_sha256"] = report[
            "dependency_graph"
        ]["sha256"]
        report["integrated_validation"]["scope_sha256"] = report["artifacts"][
            "scope"
        ]["sha256"]
        report["integrated_validation"]["system_graph_artifact_sha256"] = report[
            "artifacts"
        ]["system_graph"]["sha256"]
        report["integrated_validation"]["reconciliation"] = [
            {"item": label, "observed": value, "expected": value}
            for label, value in (
                ("G4 source revision", revision or self.source_revision),
                ("G5 source revision", revision or self.source_revision),
                ("G6 source revision", revision or self.source_revision),
                ("G6 graph revision", revision or self.source_revision),
                (
                    "G6 graph digest",
                    report["artifacts"]["system_graph"]["sha256"],
                ),
            )
        ]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        attestation = {
            "repository": self.repository,
            "source_revision": revision or self.source_revision,
            "artifact_sha256": hashlib.sha256((self.root / "dist/palaco.tar").read_bytes()).hexdigest(),
            "evidence_report_sha256": hashlib.sha256(self.report_path.read_bytes()).hexdigest(),
        }
        (self.root / "dist/attestation.json").write_text(json.dumps(attestation), encoding="utf-8")

    def file_reference(self, relative_path):
        path = self.root / relative_path
        return f"{relative_path}@{hashlib.sha256(path.read_bytes()).hexdigest()}"

    def checklist(self, decision="APPROVE", source_revision=None):
        fields = {
            "source_revision": source_revision or self.source_revision,
            "artifact": self.file_reference("dist/palaco.tar"),
            "evidence_report": self.file_reference("validation/prior-evidence.json"),
            "attestation": self.file_reference("dist/attestation.json"),
            "decision_authority": "Release Authority",
            "decision_record": "DEC-42",
            "decision": decision,
        }
        return "| Field | Value |\n|---|---|\n" + "".join(
            f"| {name} | {value} |\n" for name, value in fields.items()
        )

    def evaluate(self, **overrides):
        arguments = {
            "release_text": self.checklist(),
            "release_error": None,
            "source_revision": self.source_revision,
            "expected_repository": self.repository,
            "source_tree_clean": True,
            "prior_gates": self.prior_gates,
            "release_artifact": self.artifact,
            "release_evidence_root": self.root,
        }
        arguments.update(overrides)
        return evaluate_g9(**arguments)

    def test_release_eligibility_requires_bound_evidence_and_decision_claim(self):
        result, evidence = self.evaluate()
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(evidence["release_eligible"])
        self.assertTrue(evidence["release_approval_claimed"])
        self.assertFalse(evidence["decision_authority_authenticated"])
        self.assertTrue(evidence["attestation_binding_verified"])
        self.assertFalse(evidence["attestation_authentication_verified"])

    def test_missing_release_checklist_holds(self):
        result, _ = self.evaluate(release_text=None, release_error="missing")
        self.assertEqual(result["result"], "HOLD")

    def test_missing_required_release_field_holds(self):
        result, _ = self.evaluate(release_text="| Field | Value |\n|---|---|\n")
        self.assertEqual(result["result"], "HOLD")

    def test_invalid_release_table_header_fails(self):
        result, _ = self.evaluate(release_text="| Name | Data |\n|---|---|\n")
        self.assertEqual(result["result"], "FAIL")

    def test_duplicate_release_field_fails(self):
        text = self.checklist() + "| decision | APPROVE |\n"
        result, _ = self.evaluate(release_text=text)
        self.assertEqual(result["result"], "FAIL")

    def test_stale_release_source_is_inconclusive(self):
        result, _ = self.evaluate(release_text=self.checklist(source_revision="b" * 40))
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_short_source_revision_is_not_immutable_evidence(self):
        result, _ = self.evaluate(source_revision="abc123")
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_uppercase_source_revision_is_not_canonical(self):
        revision = "A" * 40
        result, _ = self.evaluate(
            source_revision=revision,
            release_text=self.checklist(source_revision=revision),
        )
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_dirty_source_is_inconclusive(self):
        result, _ = self.evaluate(source_tree_clean=False)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_prior_gate_hold_blocks_eligibility(self):
        gates = [*self.prior_gates]
        gates[8] = {"gate": "G8", "result": "HOLD"}
        result, evidence = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "HOLD")
        self.assertFalse(evidence["release_eligible"])

    def test_prior_gate_failure_remains_failure(self):
        gates = [*self.prior_gates]
        gates[1] = {"gate": "G1", "result": "FAIL"}
        result, _ = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "FAIL")

    def test_unhashable_prior_gate_result_is_inconclusive(self):
        gates = [*self.prior_gates]
        gates[0] = {"gate": "G0", "result": []}
        result, _ = self.evaluate(prior_gates=gates)
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_missing_artifact_holds(self):
        checklist = self.checklist().replace(
            self.file_reference("dist/palaco.tar"), f"dist/missing.tar@{'a' * 64}"
        )
        result, _ = self.evaluate(release_text=checklist)
        self.assertEqual(result["result"], "HOLD")

    def test_artifact_digest_mismatch_fails(self):
        checklist = self.checklist().replace(
            self.file_reference("dist/palaco.tar"), f"dist/palaco.tar@{'0' * 64}"
        )
        result, _ = self.evaluate(release_text=checklist)
        self.assertEqual(result["result"], "FAIL")

    def test_artifact_path_with_null_byte_fails_without_crashing(self):
        result, _ = self.evaluate(
            release_text=self.checklist().replace(
                "dist/palaco.tar@", "dist/\x00palaco.tar@"
            )
        )
        self.assertEqual(result["result"], "FAIL")

    def test_artifact_symlink_loop_fails_without_crashing(self):
        loop = self.root / "dist/loop"
        loop.symlink_to("loop")
        checklist = self.checklist().replace(
            self.file_reference("dist/palaco.tar"),
            f"dist/loop@{'a' * 64}",
        )
        result, _ = self.evaluate(release_text=checklist)
        self.assertEqual(result["result"], "FAIL")

    def test_digest_streams_large_artifact(self):
        content = b"release-data" * 200_000
        path = self.root / "dist/large.tar"
        path.write_bytes(content)
        self.assertEqual(digest(path), hashlib.sha256(content).hexdigest())

    def test_evidence_report_must_contain_all_prior_passes(self):
        gates = [*self.prior_gates]
        gates[6] = {"gate": "G6", "result": "HOLD"}
        self.write_report(gates=gates)
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "HOLD")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_prior_failure_remains_failure(self):
        gates = [*self.prior_gates]
        gates[6] = {"gate": "G6", "result": "FAIL"}
        self.write_report(gates=gates)
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(evidence["release_eligible"])

    def test_current_hold_does_not_hide_evidence_report_prior_failure(self):
        report_gates = [*self.prior_gates]
        report_gates[6] = {"gate": "G6", "result": "FAIL"}
        self.write_report(gates=report_gates)
        current_gates = [*self.prior_gates]
        current_gates[8] = {"gate": "G8", "result": "HOLD"}
        result, evidence = self.evaluate(
            release_text=self.checklist(), prior_gates=current_gates
        )
        self.assertEqual(result["result"], "FAIL")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g9_hold_does_not_create_recursive_blocker(self):
        result, evidence = self.evaluate()
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(evidence["evidence_report_g9_result"], "HOLD")

    def test_evidence_report_requires_g0_g3_input_artifact_digests(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        del report["artifacts"]["execution_plan"]["sha256"]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_rejects_artifact_path_escape(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["artifacts"]["system_graph"]["path"] = "../system-graph.json"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_dependency_graph_digest_must_match(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["dependency_graph"]["nodes"].append("unbound-package")
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_execution_layers_must_cover_topological_steps(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["execution_schedule"]["topological_order"] = ["different-step"]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_allows_valid_parallel_layer_ordering(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["execution_schedule"]["execution_layers"] = [["a", "z"], ["b"]]
        report["execution_schedule"]["topological_order"] = ["a", "b", "z"]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        attestation_path = self.root / "dist/attestation.json"
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["evidence_report_sha256"] = hashlib.sha256(
            self.report_path.read_bytes()
        ).hexdigest()
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(evidence["release_eligible"])

    def test_evidence_report_architecture_revision_must_match(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["architecture_compliance"]["system_graph_revision"] = "stale"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g7_scope_digest_must_match_input_artifact(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["scope_sha256"] = "f" * 64
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g7_reconciliation_must_match_system_graph(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["reconciliation"][-1]["observed"] = "f" * 64
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g7_plan_digest_must_match_schedule(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["execution_plan_sha256"] = "f" * 64
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_requires_consistent_integrated_ci_run_ids(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["run_id"] = "different-run"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_requires_g4_g7_ci_run_ids(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        del report["runtime_kernel_tests"]["run_id"]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_requires_revision_bound_clean_test_evidence(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["event_observability_tests"]["source_revision"] = "stale"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_requires_successful_tests_with_output_digests(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["exit_code"] = 1
        report["integrated_validation"]["output_sha256"] = "invalid"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_integrated_test_repository_must_match(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["repository"] = "different/project"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g8_requires_revision_bound_audit(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["security_validation"]["dependency_audit"]["source_revision"] = "stale"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g8_controls_must_match_verified_digests(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["security_validation"]["controls"][0]["observed_sha256"] = "0" * 64
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g8_requires_all_security_controls(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["security_validation"]["controls"].pop()
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g8_malformed_control_name_is_inconclusive(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["security_validation"]["controls"][0]["control"] = []
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_scenario_failure_cannot_support_pass_gate(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["event_observability_tests"]["scenarios"][0]["result"] = "FAILED"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_requires_complete_integrated_scenario_coverage(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["scenarios"].pop()
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_rejects_duplicate_integrated_scenarios(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        scenarios = report["integrated_validation"]["scenarios"]
        scenarios.append(dict(scenarios[0]))
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_malformed_scenario_name_is_inconclusive(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["runtime_kernel_tests"]["scenarios"][0]["name"] = []
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_malformed_integrated_scenarios_are_inconclusive(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["integrated_validation"]["scenarios"] = None
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")
        self.assertFalse(evidence["release_eligible"])

    def test_evidence_report_g9_failure_does_not_override_g0_g8(self):
        gates = [*self.prior_gates, {"gate": "G9", "result": "FAIL"}]
        self.write_report(gates=gates)
        result, evidence = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(evidence["evidence_report_g9_result"], "FAIL")

    def test_evidence_report_g9_invalid_result_is_inconclusive(self):
        gates = [*self.prior_gates, {"gate": "G9", "result": "UNKNOWN"}]
        self.write_report(gates=gates)
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_evidence_report_g9_unhashable_result_is_inconclusive(self):
        gates = [*self.prior_gates, {"gate": "G9", "result": []}]
        self.write_report(gates=gates)
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_unverifiable_evidence_report_gate_is_inconclusive(self):
        gates = [*self.prior_gates]
        gates[6] = {"gate": "G6", "result": "UNKNOWN"}
        self.write_report(gates=gates)
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_evidence_report_unhashable_gate_result_is_inconclusive(self):
        gates = [*self.prior_gates]
        gates[6] = {"gate": "G6", "result": []}
        self.write_report(gates=gates)
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_evidence_report_revision_mismatch_is_inconclusive(self):
        self.write_report(revision="stale")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_evidence_report_requires_supported_validator_format(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["validator"]["version"] = "0.9.0"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_evidence_report_format_version_must_be_integer_not_boolean(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["format_version"] = True
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_evidence_report_requires_timezone_aware_timestamp(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["generated_at"] = "2026-11-05T00:00:00"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_evidence_report_requires_gate_findings_shape(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        del report["gates"][0]["findings"]
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_evidence_report_repository_mismatch_is_inconclusive(self):
        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        report["repository"] = "different/project"
        self.report_path.write_text(json.dumps(report), encoding="utf-8")
        attestation = {
            "repository": self.repository,
            "source_revision": self.source_revision,
            "artifact_sha256": hashlib.sha256((self.root / "dist/palaco.tar").read_bytes()).hexdigest(),
            "evidence_report_sha256": hashlib.sha256(self.report_path.read_bytes()).hexdigest(),
        }
        (self.root / "dist/attestation.json").write_text(json.dumps(attestation), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_attestation_repository_mismatch_is_inconclusive(self):
        attestation_path = self.root / "dist/attestation.json"
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["repository"] = "different/project"
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_release_evidence_can_be_supplied_from_external_bundle(self):
        bundle = self.root / "external-bundle"
        (bundle / "dist").mkdir(parents=True)
        (bundle / "validation").mkdir()
        for relative_path in (
            "dist/palaco.tar",
            "dist/attestation.json",
            "validation/prior-evidence.json",
        ):
            target = bundle / relative_path
            target.write_bytes((self.root / relative_path).read_bytes())
        (bundle / "validation/release_validation.md").write_text(
            self.checklist(), encoding="utf-8"
        )
        result, evidence = self.evaluate(release_evidence_root=bundle)
        self.assertEqual(result["result"], "PASS")
        self.assertTrue(evidence["release_eligible"])

    def test_release_evidence_root_must_be_a_directory(self):
        file_path = self.root / "dist/palaco.tar"
        resolved, error = _resolve_release_evidence_dir(file_path)
        self.assertIsNone(resolved)
        self.assertEqual(error, "release evidence path is not a directory")

    def test_release_evidence_root_cannot_be_repository_ancestor(self):
        with patch("pvc_validate.ROOT", self.root / "checkout"):
            (self.root / "checkout").mkdir()
            resolved, error = _resolve_release_evidence_dir(self.root)
        self.assertIsNone(resolved)
        self.assertEqual(
            error, "release evidence directory must not contain the repository root"
        )

    def test_external_release_evidence_root_is_resolved(self):
        bundle = self.root / "external-bundle"
        bundle.mkdir()
        resolved, error = _resolve_release_evidence_dir(bundle)
        self.assertEqual(resolved, bundle.resolve())
        self.assertIsNone(error)

    def test_unresolvable_release_evidence_root_returns_error(self):
        loop = self.root / "root-loop"
        loop.symlink_to("root-loop")
        resolved, error = _resolve_release_evidence_dir(loop)
        self.assertIsNone(resolved)
        self.assertIn("could not be resolved", error)

    def test_external_checklist_artifact_has_relative_path_and_digest(self):
        bundle = self.root / "external-bundle"
        checklist = bundle / "validation/release_validation.md"
        checklist.parent.mkdir(parents=True)
        checklist.write_text(self.checklist(), encoding="utf-8")
        artifact = _artifact_in_directory(checklist, bundle)
        self.assertEqual(artifact["path"], "validation/release_validation.md")
        self.assertEqual(artifact["sha256"], hashlib.sha256(checklist.read_bytes()).hexdigest())

    def test_external_checklist_symlink_cannot_escape_bundle(self):
        bundle = self.root / "external-bundle"
        (bundle / "validation").mkdir(parents=True)
        outside = self.root / "release_validation.md"
        outside.write_text(self.checklist(), encoding="utf-8")
        checklist = bundle / "validation/release_validation.md"
        checklist.symlink_to(outside)
        self.assertIsNone(_artifact_in_directory(checklist, bundle))

    def test_external_checklist_symlink_loop_is_ignored(self):
        bundle = self.root / "external-bundle"
        (bundle / "validation").mkdir(parents=True)
        checklist = bundle / "validation/release_validation.md"
        checklist.symlink_to("release_validation.md")
        self.assertIsNone(_artifact_in_directory(checklist, bundle))

    def test_attestation_artifact_mismatch_fails(self):
        attestation_path = self.root / "dist/attestation.json"
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["artifact_sha256"] = "0" * 64
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_attestation_evidence_report_mismatch_fails(self):
        attestation_path = self.root / "dist/attestation.json"
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["evidence_report_sha256"] = "0" * 64
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "FAIL")

    def test_attestation_source_mismatch_is_inconclusive(self):
        attestation_path = self.root / "dist/attestation.json"
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        attestation["source_revision"] = "stale"
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        result, _ = self.evaluate(release_text=self.checklist())
        self.assertEqual(result["result"], "INCONCLUSIVE")

    def test_pending_decision_holds(self):
        result, _ = self.evaluate(release_text=self.checklist(decision="PENDING"))
        self.assertEqual(result["result"], "HOLD")

    def test_decision_is_normalized_before_report_rendering(self):
        result, evidence = self.evaluate(release_text=self.checklist(decision=" approve "))
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(evidence["decision"], "APPROVE")
        self.assertTrue(evidence["release_approval_claimed"])

    def test_repeated_decision_row_fails(self):
        result, _ = self.evaluate(
            release_text=self.checklist() + "| decision | REJECT |\n"
        )
        self.assertEqual(result["result"], "FAIL")

    def test_rejection_does_not_claim_approval(self):
        result, evidence = self.evaluate(release_text=self.checklist(decision="REJECT"))
        self.assertEqual(result["result"], "HOLD")
        self.assertFalse(evidence["release_eligible"])
        self.assertFalse(evidence["release_approval_claimed"])
        self.assertTrue(evidence["attestation_binding_verified"])

    def test_prior_gate_order_must_be_exact(self):
        result, _ = self.evaluate(prior_gates=list(reversed(self.prior_gates)))
        self.assertEqual(result["result"], "HOLD")


if __name__ == "__main__":
    unittest.main()
