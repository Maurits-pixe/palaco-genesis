"""WNRA-04: expose test-only content-origin and in-place mutation limitations.

These are *negative capability* probes, not claims of containment.
No untrusted paths are opened through a production PALACO entry point.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from windows_build_root_test_adapter import BuildRootTestAdapter

if os.name == "nt":
    import windows_native_relative_test_open as native


@unittest.skipUnless(os.name == "nt", "native NT fixture requires Windows")
class ContentOriginLimitationTests(unittest.TestCase):
    def test_hardlink_into_fixture_does_not_establish_origin(self):
        # Same-volume hardlinks are not reparse points; a valid root-relative
        # handle can reference bytes owned by a different directory.
        with BuildRootTestAdapter() as fixture:
            with tempfile.TemporaryDirectory(prefix="palaco-outside-origin-",
                                             dir=fixture.root.parent) as outside:
                source = Path(outside) / "source.json"
                source.write_bytes(b"OUTSIDE_ORIGIN")
                linked = fixture.root / "metadata.json"
                try:
                    os.link(source, linked)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"hardlink unavailable on this runner: {exc}")
                self.assertTrue(os.path.samefile(source, linked))
                # A successful read here is evidence of a PROVENANCE GAP,
                # not proof the opener has contained the origin of the data.
                self.assertEqual(
                    native.read_fixture_metadata_relative(fixture, "metadata.json"),
                    b"OUTSIDE_ORIGIN",
                )

    def test_inplace_mutation_after_nt_open_changes_returned_bytes(self):
        # Contrast with path-replacement tests: HANDLE retention cannot
        # promise immutable content while a writer can edit the same inode.
        with BuildRootTestAdapter() as fixture:
            path = fixture.root / "metadata.json"
            path.write_bytes(b"ORIGINAL")
            real_nt_open = native._NT_CREATE
            mutated = []

            def open_then_mutate(*args):
                result = real_nt_open(*args)
                if result >= 0:
                    path.write_bytes(b"MODIFIED")
                    mutated.append(True)
                return result

            with mock.patch.object(native, "_NT_CREATE",
                                   side_effect=open_then_mutate):
                data = native.read_fixture_metadata_relative(fixture, "metadata.json")
            self.assertEqual(mutated, [True])
            self.assertEqual(data, b"MODIFIED")
            self.assertNotEqual(data, b"ORIGINAL")


if __name__ == "__main__":
    unittest.main()
