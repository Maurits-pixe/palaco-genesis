"""WNRA-06K: direct PE import/API-set classification and already-loaded mapping.

GetModuleHandleW only observes already loaded modules in the *controller*
process. It never loads a new DLL and is not a trace of the failed worker.
All restricted-token CreateFileW probes are read-only and independent.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import sys
import unittest

from test_windows_anchor_direct_pe_import_access import direct_pe_imports
from test_windows_anchor_restricted_sid_object_open import (
    RestrictedSidObjectOpenTests, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID


def classify_import(name):
    name = name.lower()
    if name.startswith(("api-ms-win-", "ext-ms-win-")):
        return "api_set_contract"
    return "named_dll"


@unittest.skipUnless(sys.platform == "win32", "native Windows module view required")
class ApiSetModuleViewTests(unittest.TestCase):
    def setUp(self):
        self.object = RestrictedSidObjectOpenTests(
            "test_actual_read_and_execute_opens_match_recorded_dacl_probes"
        )
        self.object.setUp()
        self.fx = self.object.fx
        self.k = self.object.k
        self.k.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)
        self.k.GetModuleHandleW.restype = wintypes.HMODULE
        self.k.GetModuleFileNameW.argtypes = (
            wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
        )
        self.k.GetModuleFileNameW.restype = wintypes.DWORD

    def _already_loaded(self, name):
        # A borrowed module handle is not closed. Never call LoadLibrary.
        handle = self.k.GetModuleHandleW(name)
        if not handle:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        count = self.k.GetModuleFileNameW(handle, buffer, len(buffer))
        self.assertGreater(count, 0)
        self.assertLess(count, len(buffer))
        path = pathlib.Path(buffer.value)
        self.assertTrue(path.is_file(), "existing module file missing")
        return path

    def test_direct_import_contracts_vs_controller_module_view(self):
        windows = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        images = {
            "python": pathlib.Path(sys.executable),
            "cmd": windows / "System32" / "cmd.exe",
        }
        modules = {}
        for image, path in images.items():
            names = direct_pe_imports(path)
            self.assertTrue(names, image + " lacks imports")
            contracts = [name for name in names
                         if classify_import(name) == "api_set_contract"]
            standard = [name for name in names
                        if classify_import(name) == "named_dll"]
            observed = []
            for name in names:
                loaded = self._already_loaded(name)
                if loaded is not None:
                    observed.append((name, loaded))
            modules[image] = observed
            print(
                "WNRA06K_IMPORT image=" + image
                + " declared=" + str(len(names))
                + " api_set_contracts=" + str(len(contracts))
                + " named_dlls=" + str(len(standard))
                + " controller_loaded_matches=" + str(len(observed))
                + " no_new_module_loads=true"
                + " worker_loader_traced=false authorization=DENY"
            )
            for name in contracts[:6]:
                print(
                    "WNRA06K_CONTRACT image=" + image
                    + " contract=" + name.lower()
                    + " resolution=UNVERIFIED"
                    + " worker_loader_traced=false authorization=DENY"
                )
        self.assertTrue(
            any(modules.values()),
            "controller has no loaded module matching any direct import",
        )
        # Up to twelve distinct paths already mapped in controller. This is
        # a bounded evidence sample, never a complete dependency graph.
        sample = []
        visited = set()
        for image, mappings in modules.items():
            for name, path in mappings:
                key = str(path).casefold()
                if key not in visited and len(sample) < 12:
                    visited.add(key)
                    sample.append((image, name, path))
        source = self.fx._source()
        try:
            for variant in ("user", "builtin_users"):
                token = None
                try:
                    token = self.object.fixture._token(source, variant)
                    self.fx.token_fixture._lower_integrity(token)
                    observed = self.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    for image, name, path in sample:
                        read, read_err = self.object._object_open(
                            token, path, FILE_GENERIC_READ,
                        )
                        execute, exec_err = self.object._object_open(
                            token, path, FILE_GENERIC_EXECUTE,
                        )
                        if read:
                            self.assertEqual(read_err, 0)
                        else:
                            self.assertNotEqual(read_err, 0)
                        if execute:
                            self.assertEqual(exec_err, 0)
                        else:
                            self.assertNotEqual(exec_err, 0)
                        print(
                            "WNRA06K_MODULE variant=" + variant
                            + " image=" + image
                            + " import=" + name.lower()
                            + " loaded_in_controller=true"
                            + " read=" + str(read).lower()
                            + " read_error=" + str(read_err)
                            + " execute=" + str(execute).lower()
                            + " execute_error=" + str(exec_err)
                            + " worker_loader_traced=false"
                            + " cause_attributed=false authorization=DENY"
                        )
                finally:
                    if token:
                        self.fx.fx._close(token)
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
