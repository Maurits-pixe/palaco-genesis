"""Regression tests for deterministic SBOM generation."""

import unittest
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from generate_sbom import canonical, generate, license_expression, read_bounded_metadata, strict_json_loads


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
    def test_cargo_metadata_disk_read_is_bounded(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_bytes(b"12345678")
            with patch("generate_sbom.MAX_METADATA_BYTES", 8):
                self.assertEqual(read_bounded_metadata(path), b"12345678")
            with patch("generate_sbom.MAX_METADATA_BYTES", 7):
                with self.assertRaisesRegex(ValueError, "oversized Cargo metadata"):
                    read_bounded_metadata(path)

    def test_cargo_metadata_checks_open_descriptor_before_read(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_bytes(b"12345678")
            # Simulate a file that changes after path resolution: the opened
            # descriptor, not a separately statted pathname, is authoritative.
            with patch("generate_sbom.MAX_METADATA_BYTES", 8):
                with patch("generate_sbom.os.fstat", return_value=SimpleNamespace(st_size=9, st_mode=stat.S_IFREG)) as fstat:
                    with self.assertRaisesRegex(ValueError, "oversized Cargo metadata"):
                        read_bounded_metadata(path)
                    fstat.assert_called_once()
                # A file that grows after fstat must still be rejected by
                # the bounded limit-plus-one read.
                path.write_bytes(b"123456789")
                with patch("generate_sbom.os.fstat", return_value=SimpleNamespace(st_size=7, st_mode=stat.S_IFREG)):
                    with self.assertRaisesRegex(ValueError, "oversized Cargo metadata"):
                        read_bounded_metadata(path)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO required")
    def test_cargo_metadata_rejects_fifo_without_blocking(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.fifo"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_bounded_metadata(path)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "nofollow required")
    def test_cargo_metadata_rejects_symlink(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            target = Path(directory) / "target.json"
            target.write_bytes(b"{}")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                read_bounded_metadata(path)

    def test_cargo_metadata_symlink_rejected_without_nofollow(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            target = Path(directory) / "target.json"
            target.write_bytes(b"{}")
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with patch("generate_sbom.os.O_NOFOLLOW", 0, create=True):
                with self.assertRaisesRegex(ValueError, "path does not match"):
                    read_bounded_metadata(path)

    def test_cargo_metadata_path_replacement_rejected_without_nofollow(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_bytes(b"{}")
            original_stat = os.stat

            def different_inode(candidate, *, follow_symlinks=True):
                result = original_stat(candidate, follow_symlinks=follow_symlinks)
                if not follow_symlinks and candidate == path:
                    return SimpleNamespace(st_mode=result.st_mode, st_dev=result.st_dev,
                                           st_ino=result.st_ino + 1)
                return result

            with patch("generate_sbom.os.O_NOFOLLOW", 0, create=True):
                with patch("generate_sbom.os.stat", side_effect=different_inode):
                    with self.assertRaisesRegex(ValueError, "path does not match"):
                        read_bounded_metadata(path)

    def test_non_finite_json_values_rejected(self):
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(value=literal):
                with self.assertRaisesRegex(ValueError, "non-finite JSON"):
                    strict_json_loads(b'{"nested":{"value":' + literal + b'}}')
        with self.assertRaisesRegex(ValueError, "Out of range"):
            canonical({"value": float("nan")})

    def test_malformed_package_and_identity_inputs_fail_closed(self):
        cases = (
            ("null commit", METADATA, None, 0, "commit"),
            ("boolean epoch", METADATA, COMMIT, True, "source epoch"),
            ("negative epoch", METADATA, COMMIT, -1, "source epoch"),
            ("null package", {**METADATA, "packages": [None]}, COMMIT, 0, "malformed cargo package"),
            ("missing version", {**METADATA, "packages": [{"id": "pkg-a", "name": "a"}]}, COMMIT, 0, "malformed cargo package"),
            ("invalid license", {**METADATA, "packages": [{"id": "pkg-a", "name": "a", "version": "1", "license": []}]}, COMMIT, 0, "malformed cargo package"),
            ("missing members", {key: value for key, value in METADATA.items() if key != "workspace_members"}, COMMIT, 0, "workspace members"),
            ("duplicate members", {**METADATA, "workspace_members": ["pkg-a", "pkg-a"]}, COMMIT, 0, "duplicate workspace members"),
        )
        for label, metadata, commit, epoch, error in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error):
                    generate(metadata, commit, epoch)

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
            ("resolve node", {**METADATA, "resolve": {"nodes": METADATA["resolve"]["nodes"] + [{"id": "pkg-unknown", "dependencies": []}]}}),
            ("dependency", {**METADATA, "resolve": {"nodes": [{"id": "pkg-a", "dependencies": ["pkg-unknown"]}, METADATA["resolve"]["nodes"][1]]}}),
        )
        for label, metadata in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "unknown"):
                    generate(metadata, COMMIT, 0)

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

    def test_incomplete_or_malformed_resolve_graph_fails_closed(self):
        good_nodes = METADATA["resolve"]["nodes"]
        cases = (
            ("package omitted", [good_nodes[0]], "missing from resolve"),
            ("duplicate node", good_nodes + [good_nodes[0]], "duplicate resolve"),
            ("non-object node", good_nodes + [None], "malformed resolve"),
            ("missing dependencies", [{"id": "pkg-a"}, good_nodes[1]], "malformed dependencies"),
            ("null dependencies", [{"id": "pkg-a", "dependencies": None}, good_nodes[1]], "malformed dependencies"),
            ("non-string dependency", [{"id": "pkg-a", "dependencies": [None]}, good_nodes[1]], "malformed dependencies"),
        )
        for label, nodes, error in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error):
                    generate({**METADATA, "resolve": {"nodes": nodes}}, COMMIT, 0)

    def test_missing_or_duplicate_input_fails_closed(self):
        with self.assertRaises(ValueError):
            generate({"packages": []}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate({**METADATA, "packages": METADATA["packages"] * 2}, COMMIT, 0)
        with self.assertRaises(ValueError):
            generate(METADATA, "not-a-sha", 0)

    def test_detailed_dependency_records_are_consistent(self):
        nodes = METADATA["resolve"]["nodes"]
        detailed = [
            {**nodes[0], "deps": [{"name": "alias_b", "pkg": "pkg-b", "dep_kinds": []}]},
            {**nodes[1], "deps": []},
        ]
        self.assertEqual(canonical(generate(METADATA, COMMIT, 0)), canonical(generate(
            {**METADATA, "resolve": {"nodes": detailed}}, COMMIT, 0
        )))
        cases = (
            ("missing detail", [{**detailed[0], "deps": []}, detailed[1]], "disagree"),
            ("unexpected detail", [{**detailed[0], "deps": detailed[0]["deps"] + [{"name": "self", "pkg": "pkg-a", "dep_kinds": []}]}, detailed[1]], "disagree"),
            ("null detail", [{**detailed[0], "deps": None}, detailed[1]], "malformed detailed"),
            ("bad package id", [{**detailed[0], "deps": [{"name": "b", "pkg": None, "dep_kinds": []}]}, detailed[1]], "malformed detailed"),
            ("bad dep kinds", [{**detailed[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": None}]}, detailed[1]], "malformed detailed"),
            ("bad dep kind element", [{**detailed[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": ["dev"]}]}, detailed[1]], "malformed detailed"),
            ("missing dep kind target", [{**detailed[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": [{"kind": "dev"}]}]}, detailed[1]], "malformed detailed"),
            ("bad dep kind value", [{**detailed[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": [{"kind": "unknown", "target": None}]}]}, detailed[1]], "malformed detailed"),
            ("bad target type", [{**detailed[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": [{"kind": None, "target": 1}]}]}, detailed[1]], "malformed detailed"),
            ("duplicate flat edge", [{**detailed[0], "dependencies": ["pkg-b", "pkg-b"]}, detailed[1]], "duplicate dependencies"),
        )
        for label, invalid_nodes, error in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error):
                    generate({**METADATA, "resolve": {"nodes": invalid_nodes}}, COMMIT, 0)

    def test_cargo_format_one_requires_complete_details_and_valid_root(self):
        nodes = METADATA["resolve"]["nodes"]
        valid_nodes = [
            {**nodes[0], "deps": [{"name": "b", "pkg": "pkg-b", "dep_kinds": []}]},
            {**nodes[1], "deps": []},
        ]
        good = {**METADATA, "format_version": 1, "resolve": {"root": "pkg-a", "nodes": valid_nodes}}
        self.assertEqual(len(generate(good, COMMIT, 0)["packages"]), 2)
        cases = (
            ("absent detail", {**good, "resolve": {"root": "pkg-a", "nodes": nodes}}, "missing detailed"),
            ("unknown root", {**good, "resolve": {"root": "unknown", "nodes": valid_nodes}}, "invalid resolve root"),
            ("external root", {**good, "resolve": {"root": "pkg-b", "nodes": valid_nodes}}, "invalid resolve root"),
            ("invalid format", {**good, "format_version": 2}, "unsupported"),
        )
        for label, invalid, error in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error):
                    generate(invalid, COMMIT, 0)


if __name__ == "__main__":
    unittest.main()

