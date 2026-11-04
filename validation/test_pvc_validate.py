import unittest
from unittest.mock import patch

from pvc_validate import (
    _dependency_graph_digest,
    _ordering_approval_digest,
    _repository_identity,
    evaluate_g0,
    evaluate_g1,
    evaluate_g2,
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


if __name__ == "__main__":
    unittest.main()
