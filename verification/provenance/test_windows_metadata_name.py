"""Pure lexical tests for a proposed Windows trusted-root filename boundary."""

import unittest

from windows_metadata_name import validate_windows_metadata_basename


class WindowsMetadataNameTests(unittest.TestCase):
    def test_simple_basename(self):
        for value in ("metadata.json", "Cargo-Metadata_01.json", "évidence.json"):
            with self.subTest(value=value):
                self.assertEqual(validate_windows_metadata_basename(value), value)

    def test_reject_path_escapes_and_ambiguous_forms(self):
        cases = (
            "", ".", "..", "../meta.json", r"..\meta.json", r"folder\meta.json",
            "folder/meta.json", r"C:\meta.json", "C:meta.json",
            r"\\server\share\meta.json", r"\\?\C:\meta.json",
            "meta.json:ads", "meta.json.", "meta.json ", "trailing ",
            "bad<name", "bad>name", 'bad"name', "bad|name", "bad?name",
            "bad*name", "bad\x00name", "bad\x1fname", "CON", "con.txt",
            "PRN.json", "AUX", "NUL", "COM1", "com9.json", "LPT1",
            "LPT9.txt", "COM¹.txt", "LPT².txt",
        )
        for value in cases:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    validate_windows_metadata_basename(value)

    def test_reject_non_string_and_overlong(self):
        for value in (None, 7, b"metadata.json", "x" * 256):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    validate_windows_metadata_basename(value)
