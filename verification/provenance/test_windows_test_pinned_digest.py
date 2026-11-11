"""WNRA-04C native Windows-only digest gate regressions.

A matching hash demonstrates byte equivalence only, never authenticated origin.
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from windows_build_root_test_adapter import BuildRootTestAdapter

if os.name == "nt":
    import windows_native_relative_test_open as native
    from windows_test_pinned_digest import read_fixture_with_pinned_digest


def sha(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(os.name == "nt", "Windows NT fixture required")
class PinnedDigestFixtureTests(unittest.TestCase):
    def test_matching_pinned_digest_returns_exact_bytes(self):
        with BuildRootTestAdapter() as fixture:
            (fixture.root / "metadata.json").write_bytes(b"ORIGINAL")
            self.assertEqual(
                read_fixture_with_pinned_digest(fixture, "metadata.json",
                                                sha(b"ORIGINAL")),
                b"ORIGINAL",
            )

    def test_missing_malformed_and_uppercase_digest_deny_before_open(self):
        with BuildRootTestAdapter() as fixture:
            (fixture.root / "metadata.json").write_bytes(b"ORIGINAL")
            for supplied in (None, "", b"0" * 64, "z" * 64, "ABC" * 21 + "A",
                             sha(b"ORIGINAL").upper()):
                with self.subTest(supplied=supplied):
                    with mock.patch(
                        "windows_test_pinned_digest.read_fixture_metadata_relative",
                        side_effect=AssertionError("filesystem must not open"),
                    ) as opener:
                        with self.assertRaises(ValueError):
                            read_fixture_with_pinned_digest(
                                fixture, "metadata.json", supplied
                            )
                        opener.assert_not_called()

    def test_wrong_expected_digest_denies_consumption(self):
        with BuildRootTestAdapter() as fixture:
            (fixture.root / "metadata.json").write_bytes(b"ALTERED")
            with self.assertRaisesRegex(ValueError, "differ"):
                read_fixture_with_pinned_digest(fixture, "metadata.json",
                                                sha(b"ORIGINAL"))

    def test_inplace_mutation_between_open_and_read_denied(self):
        with BuildRootTestAdapter() as fixture:
            path = fixture.root / "metadata.json"
            path.write_bytes(b"ORIGINAL")
            real_nt_create = native._NT_CREATE
            observed = []

            def mutate_after_open(*args):
                status = real_nt_create(*args)
                if status >= 0:
                    path.write_bytes(b"MODIFIED")
                    observed.append(True)
                return status

            with mock.patch.object(native, "_NT_CREATE",
                                   side_effect=mutate_after_open):
                with self.assertRaisesRegex(ValueError, "differ"):
                    read_fixture_with_pinned_digest(
                        fixture, "metadata.json", sha(b"ORIGINAL")
                    )
            self.assertEqual(observed, [True])

    def test_hardlink_with_matching_digest_does_not_prove_origin(self):
        with BuildRootTestAdapter() as fixture:
            with tempfile.TemporaryDirectory(prefix="palaco-outside-",
                                             dir=fixture.root.parent) as outside:
                source = Path(outside) / "source.json"
                source.write_bytes(b"OUTSIDE")
                try:
                    os.link(source, fixture.root / "metadata.json")
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"hardlink unavailable: {exc}")
                # Deliberate LIMITATION: if a caller pins an attacker's bytes,
                # the matching hash cannot authenticate their provenance.
                self.assertEqual(
                    read_fixture_with_pinned_digest(fixture, "metadata.json",
                                                    sha(b"OUTSIDE")),
                    b"OUTSIDE",
                )


if __name__ == "__main__":
    unittest.main()
