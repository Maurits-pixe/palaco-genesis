"""WNRA-06J: bounded, read-only direct PE import dependency access probe.

Parses on-disk PE import descriptors; not the Windows loader's resolution
trace. Checks only DLL paths physically found beside image or in System32.
No ACL/audit changes, imports executed, production release or authority.
"""
import os
import pathlib
import struct
import sys
import unittest

from test_windows_anchor_restricted_sid_object_open import (
    RestrictedSidObjectOpenTests, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID


def direct_pe_imports(path):
    """Get on-disk import directory names with strict bounds, not delay-loads."""
    data = pathlib.Path(path).read_bytes()
    def u16(pos):
        if pos < 0 or pos + 2 > len(data):
            raise ValueError("PE u16 outside file")
        return struct.unpack_from("<H", data, pos)[0]
    def u32(pos):
        if pos < 0 or pos + 4 > len(data):
            raise ValueError("PE u32 outside file")
        return struct.unpack_from("<I", data, pos)[0]
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not MZ")
    pe = u32(0x3c)
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not PE")
    coff = pe + 4
    section_count = u16(coff + 2)
    optional_size = u16(coff + 16)
    optional = coff + 20
    if optional + optional_size > len(data):
        raise ValueError("invalid optional header")
    magic = u16(optional)
    if magic == 0x20b:  # PE32+
        directory = optional + 112
    elif magic == 0x10b:  # PE32
        directory = optional + 96
    else:
        raise ValueError("unknown PE optional-header magic")
    if directory + 16 > optional + optional_size:
        raise ValueError("missing import directory")
    imports_rva = u32(directory + 8)
    imports_size = u32(directory + 12)
    sections = []
    header = optional + optional_size
    if section_count > 96 or header + section_count * 40 > len(data):
        raise ValueError("invalid section table")
    for i in range(section_count):
        start = header + i * 40
        sections.append((
            u32(start + 12), u32(start + 8),
            u32(start + 16), u32(start + 20),
        ))
    def offset(rva, length=1):
        for base, virtual, raw_size, raw_offset in sections:
            if base <= rva and rva - base + length <= raw_size:
                pos = raw_offset + rva - base
                if pos + length <= len(data):
                    return pos
        raise ValueError("RVA outside backed sections")
    if imports_rva == 0 or imports_size == 0:
        return []
    result = []
    seen = set()
    # Hard cap on corrupt descriptor tables. One entry is 20 bytes.
    for index in range(min(256, max(1, imports_size // 20))):
        start = offset(imports_rva + index * 20, 20)
        descriptor = data[start:start + 20]
        if descriptor == bytes(20):
            break
        name_rva = u32(start + 12)
        start_name = offset(name_rva)
        end = data.find(b"\x00", start_name, min(len(data), start_name + 260))
        if end < 0:
            raise ValueError("unterminated import name")
        name = data[start_name:end].decode("ascii")
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError("unsafe import name")
        folded = name.lower()
        if folded not in seen:
            seen.add(folded)
            result.append(name)
    return result


@unittest.skipUnless(sys.platform == "win32", "native Windows PE fixture required")
class DirectPeImportAccessTests(unittest.TestCase):
    def setUp(self):
        self.open = RestrictedSidObjectOpenTests(
            "test_actual_read_and_execute_opens_match_recorded_dacl_probes"
        )
        self.open.setUp()
        self.fx = self.open.fx

    def test_bounded_import_names_and_actual_opens(self):
        windows = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        images = {
            "python": pathlib.Path(sys.executable),
            "cmd": windows / "System32" / "cmd.exe",
        }
        # Parsing is performed by the trusted test controller, without
        # executing or resolving dependencies as a Windows loader would.
        selected = {}
        for image, exe in images.items():
            self.assertTrue(exe.is_file())
            names = direct_pe_imports(exe)
            self.assertTrue(names, image + " has no direct PE imports")
            resolved = []
            unresolved = 0
            for name in names:
                file = next(
                    (p for p in (
                        exe.parent / name,
                        windows / "System32" / name,
                    ) if p.is_file()),
                    None,
                )
                if file is None:
                    unresolved += 1
                elif len(resolved) < 12:
                    resolved.append((name, file))
            self.assertTrue(resolved, image + " has no sampled resolved imports")
            selected[image] = resolved
            print(
                "WNRA06J_IMPORT image=" + image
                + " declared=" + str(len(names))
                + " sampled=" + str(len(resolved))
                + " unresolved=" + str(unresolved)
                + " resolution_scope=adjacent_or_system32"
                + " loader_trace=false authorization=DENY"
            )
        source = self.fx._source()
        try:
            for variant in ("user", "builtin_users"):
                token = None
                try:
                    token = self.open.fixture._token(source, variant)
                    self.fx.token_fixture._lower_integrity(token)
                    observed = self.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    for image, paths in selected.items():
                        for name, file in paths:
                            read, r_code = self.open._object_open(
                                token, file, FILE_GENERIC_READ,
                            )
                            execute, x_code = self.open._object_open(
                                token, file, FILE_GENERIC_EXECUTE,
                            )
                            if read:
                                self.assertEqual(r_code, 0)
                            else:
                                self.assertNotEqual(r_code, 0)
                            if execute:
                                self.assertEqual(x_code, 0)
                            else:
                                self.assertNotEqual(x_code, 0)
                            print(
                                "WNRA06J_DEPENDENCY variant=" + variant
                                + " image=" + image
                                + " dll=" + name
                                + " read=" + str(read).lower()
                                + " read_error=" + str(r_code)
                                + " execute=" + str(execute).lower()
                                + " execute_error=" + str(x_code)
                                + " actual_open=true loader_trace=false"
                                + " cause_attributed=false authorization=DENY"
                            )
                finally:
                    if token:
                        self.fx.fx._close(token)
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
