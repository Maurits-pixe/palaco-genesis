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
    "resolve": {"nodes": [{"id": "pkg-a", "dependencies": ["pkg-b"]}, {"id": "pkg-b", "dependencies": []}]},
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

    def test_unresolved_cargo_references_fail_closed(self):
        cases = (
            ("workspace member", {**METADATA, "workspace_members": ["pkg-a", "pkg-unknown"]}),
            ("resolve node", {**METADATA, "resolve": {"nodes": [{"id": "pkg-unknown", "dependencies": []}]}}),
            ("dependency", {**METADATA, "resolve": {"nodes": [{"id": "pkg-a", "dependencies": ["pkg-unknown"]}, {"id": "pkg-b", "dependencies": []}]}}),
        )
        for label, metadata in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "unknown"):
                    generate(metadata, COMMIT, 0)

    def test_incomplete_or_duplicate_resolve_nodes_fail_closed(self):
        cases = (
            ("missing dependency package node", {"nodes": [{"id": "pkg-a", "dependencies": ["pkg-b"]}]}),
            ("missing workspace package node", {"nodes": [{"id": "pkg-b", "dependencies": []}]}),
            ("duplicate node", {"nodes": METADATA["resolve"]["nodes"] + [METADATA["resolve"]["nodes"][0]]}),
        )
        for label, resolve in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "resolve node"):
                    generate({**METADATA, "resolve": resolve}, COMMIT, 0)

    def test_missing_or_empty_resolve_graph_fails_closed(self):
        cases = (
            ("missing", {key: value for key, value in METADATA.items() if key != "resolve"}),
            ("null", {**METADATA, "resolve": None}),
            ("empty object", {**METADATA, "resolve": {}}),
            ("empty nodes", {**METADATA, "resolve": {"nodes": []}}),
            ("invalid nodes", {**METADATA, "resolve": {"nodes": None}}),
        )
        for label, metadata in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "resolve"):
                    generate(metadata, COMMIT, 0)

    def test_missing_or_duplicate_input_fails_closed(self):
        with self.assertRaises(ValueError):
            generate({"packages": []}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate({**METADATA, "packages": METADATA["packages"] * 2}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate(METADATA, "not-a-sha", 0)


if __name__ == "__main__":
    unittest.main()
