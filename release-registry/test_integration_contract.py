"""Offline unified integration contract negative test suite."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from integration_contract import ContractError, SCHEMA, validate_integration

IDS = ("palaco-one", "rio", "mundo", "citadel", "neo-os")


class IntegrationContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.modules = [
            {"id": name, "entrypoint": name + "/index.html", "requires": []}
            for name in IDS
        ]
        for name in IDS:
            directory = self.root / name
            directory.mkdir()
            (directory / "index.html").write_text("<!doctype html><title>candidate</title>")
        self.save()

    def save(self):
        (self.root / "module-contract.json").write_text(
            json.dumps({"schema": SCHEMA, "modules": self.modules}), encoding="utf-8")
        files = [
            p for p in self.root.rglob("*")
            if p.is_file() and p.name != "package-integrity.json"
        ]
        entries = [
            {"path": p.relative_to(self.root).as_posix(),
             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(files)
        ]
        (self.root / "package-integrity.json").write_text(json.dumps({
            "schema": "palaco-package-integrity/v1", "files": entries
        }), encoding="utf-8")

    def rejects(self):
        self.save()
        with self.assertRaises(ContractError):
            validate_integration(self.root)

    def test_valid(self):
        self.assertEqual(validate_integration(self.root), tuple(sorted(IDS)))

    def test_missing_module(self):
        self.modules.pop()
        self.rejects()

    def test_unknown_module(self):
        self.modules[0]["id"] = "unauthorized"
        self.rejects()

    def test_duplicate_module(self):
        self.modules[1]["id"] = "palaco-one"
        self.rejects()

    def test_unlisted_entrypoint(self):
        self.modules[0]["entrypoint"] = "palaco-one/missing.html"
        self.rejects()

    def test_cross_module_entrypoint(self):
        self.modules[0]["entrypoint"] = "rio/index.html"
        self.rejects()

    def test_self_dependency(self):
        self.modules[0]["requires"] = ["palaco-one"]
        self.rejects()

    def test_cycle(self):
        self.modules[0]["requires"] = ["rio"]
        self.modules[1]["requires"] = ["palaco-one"]
        self.rejects()

    def test_unknown_dependency(self):
        self.modules[0]["requires"] = ["external"]
        self.rejects()

    def test_duplicate_dependency(self):
        self.modules[0]["requires"] = ["rio", "rio"]
        self.rejects()

    def test_contract_not_listed(self):
        self.save()
        path = self.root / "package-integrity.json"
        manifest = json.loads(path.read_text())
        manifest["files"] = [f for f in manifest["files"]
                             if f["path"] != "module-contract.json"]
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ContractError):
            validate_integration(self.root)

    def test_package_mutation(self):
        self.save()
        (self.root / "rio/index.html").write_text("changed")
        with self.assertRaises(ContractError):
            validate_integration(self.root)

    def test_unknown_module_field(self):
        self.modules[0]["authorized"] = True
        self.rejects()


if __name__ == "__main__":
    unittest.main()
