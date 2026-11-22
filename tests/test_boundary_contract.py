"""Regression tests for PALACO fail-closed integration interface declarations."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("boundary_validator", ROOT / "tools" / "validate_boundary_contract.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class BoundaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((ROOT / "ecosystem" / "integration-registry.v0.1.json").read_text(encoding="utf-8"))
        cls.contract = json.loads((ROOT / "ecosystem" / "boundary-contract.v0.1.json").read_text(encoding="utf-8"))

    def candidate(self):
        return copy.deepcopy(self.contract)

    def rejects(self, contract, fragment):
        errors = mod.validate(self.registry, contract)
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_valid_contract(self):
        self.assertEqual(mod.validate(self.registry, self.candidate()), [])

    def test_release_gate(self):
        data = self.candidate()
        data["release_gate"] = "GO"
        self.rejects(data, "release gates")

    def test_unregistered_edge(self):
        data = self.candidate()
        data["edges"][0]["provider"] = "citadel"
        self.rejects(data, "dependency not registered")

    def test_unknown_module(self):
        data = self.candidate()
        data["edges"][0]["provider"] = "ghost"
        self.rejects(data, "unknown module")

    def test_duplicate_edge(self):
        data = self.candidate()
        data["edges"].append(copy.deepcopy(data["edges"][0]))
        self.rejects(data, "duplicate interface")

    def test_missing_authentication(self):
        data = self.candidate()
        data["edges"][0]["authentication"] = "optional"
        self.rejects(data, "authentication must be required")

    def test_ui_only_authorization_rejected(self):
        data = self.candidate()
        data["edges"][0]["authorization"] = "frontend-only"
        self.rejects(data, "provider authorization required")

    def test_offline_session_issuance_rejected(self):
        data = self.candidate()
        data["edges"][2]["offline_behavior"] = "queue-untrusted"
        self.rejects(data, "must deny offline")

    def test_unknown_offline_behavior(self):
        data = self.candidate()
        data["edges"][0]["offline_behavior"] = "allow"
        self.rejects(data, "invalid offline behavior")

    def test_runtime_activation_rejected(self):
        data = self.candidate()
        data["edges"][0]["runtime_enabled"] = True
        self.rejects(data, "runtime must be disabled")

    def test_missing_required_field(self):
        data = self.candidate()
        del data["edges"][0]["authentication"]
        self.rejects(data, "missing required fields")

    def test_invalid_data_class(self):
        data = self.candidate()
        data["edges"][0]["data_class"] = "admin-password"
        self.rejects(data, "unsupported data class")

    def test_empty_purpose(self):
        data = self.candidate()
        data["edges"][0]["purpose"] = ""
        self.rejects(data, "missing purpose")

    def test_nonstring_data_class(self):
        data = self.candidate()
        data["edges"][0]["data_class"] = {"unexpected": "object"}
        self.rejects(data, "unsupported data class")

    def test_nonstring_offline_behavior(self):
        data = self.candidate()
        data["edges"][0]["offline_behavior"] = ["deny"]
        self.rejects(data, "invalid offline behavior")

    def test_nonstring_dependency_in_registry(self):
        registry = copy.deepcopy(self.registry)
        registry["modules"][0]["depends_on"] = [{"bad": "dependency"}]
        errors = mod.validate(registry, self.candidate())
        self.assertTrue(any("dependency not registered" in e for e in errors), errors)

    def test_empty_edges(self):
        data = self.candidate()
        data["edges"] = []
        self.rejects(data, "nonempty array")


if __name__ == "__main__":
    unittest.main()
