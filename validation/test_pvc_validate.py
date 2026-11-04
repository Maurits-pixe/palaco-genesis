import unittest
from unittest.mock import patch

from pvc_validate import _repository_identity, evaluate_g0, evaluate_g1


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


if __name__ == "__main__":
    unittest.main()
