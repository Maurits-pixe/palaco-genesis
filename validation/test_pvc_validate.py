import unittest
from unittest.mock import patch

from pvc_validate import (
    _canonical_sha256,
    _dependency_graph_digest,
    _ordering_approval_digest,
    _repository_identity,
    evaluate_g0,
    evaluate_g1,
    evaluate_g2,
    evaluate_g3,
    evaluate_g4,
    evaluate_g5,
    evaluate_g6,
    evaluate_g7,
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


if __name__ == "__main__":
    unittest.main()
