"""Regression tests for deterministic SBOM generation."""

import unittest

from generate_sbom import canonical, generate, license_expression


COMMIT = "a" * 40
METADATA = {
    "packages": [
        {"id": "pkg-b", "name": "b", "version": "1.0.0", "license": None},
        {"id": "pkg-a", "name": "a", "version": "0.1.0", "license": "MIT"},
    ],
    "workspace_members": ["pkg-a"],
    "resolve": {"nodes": [{"id": "pkg-a", "dependencies": ["pkg-b"]}]},
}


class SbomTests(unittest.TestCase):
    def test_legacy_cargo_license_choice_is_spdx_expression(self):
        self.assertEqual(license_expression("MIT/Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(license_expression("Apache-2.0"), "Apache-2.0")
        self.assertEqual(license_expression(None), "NOASSERTION")

    def test_deterministic_under_input_reordering(self):
        first = generate(METADATA, COMMIT, 0)
        reversed_input = {**METADATA, "packages": list(reversed(METADATA["packages"]))}
        self.assertEqual(canonical(first), canonical(generate(reversed_input, COMMIT, 0)))
        self.assertEqual(first["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(first["packages"]), 2)
        self.assertEqual(len(first["relationships"]), 2)

    def test_missing_or_duplicate_input_fails_closed(self):
        with self.assertRaises(ValueError):
            generate({"packages": []}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate({**METADATA, "packages": METADATA["packages"] * 2}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate(METADATA, "not-a-sha", 0)


if __name__ == "__main__":
    unittest.main()
