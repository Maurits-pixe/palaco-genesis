"""Negative and positive tests for the design-time PALACO integration registry."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "validate_integration_registry.py"
REGISTRY = ROOT / "ecosystem" / "integration-registry.v0.1.json"
spec = importlib.util.spec_from_file_location("integration_validator", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class IntegrationRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads(REGISTRY.read_text(encoding="utf-8"))

    def changed(self):
        return copy.deepcopy(self.original)

    def assert_rejected(self, candidate, fragment):
        errors = validator.validate(candidate)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_canonical_registry(self):
        self.assertEqual(validator.validate(self.changed()), [])

    def test_rejects_non_object(self):
        self.assert_rejected([], "must be an object")

    def test_rejects_unsupported_schema(self):
        data = self.changed()
        data["schema_version"] = "99.0"
        self.assert_rejected(data, "schema_version")

    def test_rejects_release_gate_open(self):
        data = self.changed()
        data["release_gate"] = "GO"
        self.assert_rejected(data, "release_gate")

    def test_rejects_runtime_enabled(self):
        data = self.changed()
        data["modules"][0]["runtime_enabled"] = True
        self.assert_rejected(data, "runtime_enabled")

    def test_rejects_changed_stage(self):
        data = self.changed()
        data["modules"][0]["stage"] = "deployed"
        self.assert_rejected(data, "stage must be proposed")

    def test_rejects_duplicate_ids(self):
        data = self.changed()
        data["modules"].append(copy.deepcopy(data["modules"][0]))
        self.assert_rejected(data, "duplicate id")

    def test_rejects_unknown_dependency(self):
        data = self.changed()
        data["modules"][0]["depends_on"] = ["missing-component"]
        self.assert_rejected(data, "unknown dependency")

    def test_rejects_self_dependency(self):
        data = self.changed()
        data["modules"][0]["depends_on"] = ["palaco-database"]
        self.assert_rejected(data, "self dependency")

    def test_rejects_direct_cycle(self):
        data = self.changed()
        data["modules"][0]["depends_on"] = ["palaco-one"]
        self.assert_rejected(data, "dependency cycle")

    def test_rejects_duplicate_edges(self):
        data = self.changed()
        data["modules"][1]["depends_on"] *= 2
        self.assert_rejected(data, "duplicate dependencies")

    def test_rejects_invalid_dependency_type(self):
        data = self.changed()
        data["modules"][0]["depends_on"] = "palaco-one"
        self.assert_rejected(data, "depends_on must be an array")

    def test_rejects_invalid_identifier(self):
        data = self.changed()
        data["modules"][0]["id"] = "PALACO DATABASE"
        self.assert_rejected(data, "invalid id")

    def test_rejects_empty_role(self):
        data = self.changed()
        data["modules"][0]["role"] = ""
        self.assert_rejected(data, "role must be nonempty")

    def test_rejects_nonstring_dependency(self):
        data = self.changed()
        data["modules"][0]["depends_on"] = [{"invalid": "dependency"}]
        self.assert_rejected(data, "depends_on must be an array")

    def test_rejects_empty_modules(self):
        data = self.changed()
        data["modules"] = []
        self.assert_rejected(data, "nonempty array")


if __name__ == "__main__":
    unittest.main()
