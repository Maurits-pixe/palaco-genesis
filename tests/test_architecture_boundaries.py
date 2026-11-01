"""Positive and negative tests for FCP-002-CORE-001."""
from pathlib import Path
import tempfile
import unittest

from scripts.verify_core_boundaries import check_boundaries


class BoundaryTests(unittest.TestCase):
    def make_workspace(self, foundation_extra="", constitution_extra=""):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/palaco-foundation", '
            '"crates/palaco-constitution", "crates/palaco-runtime"]\n',
            encoding="utf-8",
        )
        for name, extra in (
            ("palaco-foundation", foundation_extra),
            ("palaco-constitution", constitution_extra),
            ("palaco-runtime", ""),
        ):
            directory = root / "crates" / name
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\n{extra}',
                encoding="utf-8",
            )
        self.addCleanup(temporary.cleanup)
        return root

    def test_clean_workspace_passes(self):
        self.assertEqual(check_boundaries(self.make_workspace()), [])

    def test_foundation_runtime_dependency_fails(self):
        root = self.make_workspace('[dependencies]\npalaco-runtime = "0.1"\n')
        self.assertTrue(check_boundaries(root))

    def test_constitution_renamed_dependency_fails(self):
        root = self.make_workspace(
            constitution_extra='[dependencies]\nrenamed = { package = "palaco-runtime", version = "0.1" }\n'
        )
        self.assertTrue(check_boundaries(root))

    def test_target_specific_dev_dependency_fails(self):
        root = self.make_workspace(
            foundation_extra="[target.'cfg(unix)'.dev-dependencies]\npalaco-runtime = \"0.1\"\n"
        )
        self.assertTrue(check_boundaries(root))

    def test_path_alias_without_package_fails(self):
        root = self.make_workspace(
            foundation_extra='[dependencies]\nobscured = { path = "../palaco-runtime" }\n'
        )
        self.assertTrue(check_boundaries(root))

    def test_missing_protected_workspace_member_fails_closed(self):
        root = self.make_workspace()
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/palaco-foundation", "crates/palaco-runtime"]\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "protected crates missing"):
            check_boundaries(root)


if __name__ == "__main__":
    unittest.main()
