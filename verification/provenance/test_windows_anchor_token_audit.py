"""WNRA-05Y: native Windows access-token observations and DENY pre-resume gate.

Test-only instrumentation. Never treat observed token equivalence as a sandbox.
"""
import ctypes
from ctypes import wintypes
import pathlib
import sys
import tempfile
import unittest

from test_windows_anchor_suspended_job_launch import (
    SuspendedJobLaunchTests, WAIT_OBJECT_0, WAIT_TIMEOUT,
)

TOKEN_QUERY = 0x0008
TOKEN_PRIVILEGES = 3
TOKEN_ELEVATION = 20
TOKEN_INTEGRITY_LEVEL = 25

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

@unittest.skipUnless(sys.platform == "win32", "Windows access tokens required")
class TokenAuditTests(unittest.TestCase):
    def setUp(self):
        # Reuse the exact suspended-launch test setup without production APIs.
        self.fixture = SuspendedJobLaunchTests("test_abort_before_resume_never_runs_worker")
        self.fixture.setUp()
        self.k = self.fixture.k
        a = ctypes.WinDLL("advapi32", use_last_error=True)
        self.a = a
        a.OpenProcessToken.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
        )
        a.OpenProcessToken.restype = wintypes.BOOL
        a.GetTokenInformation.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        a.GetTokenInformation.restype = wintypes.BOOL
        a.IsTokenRestricted.argtypes = (wintypes.HANDLE,)
        a.IsTokenRestricted.restype = wintypes.BOOL
        a.GetSidSubAuthorityCount.argtypes = (ctypes.c_void_p,)
        a.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        a.GetSidSubAuthority.argtypes = (ctypes.c_void_p, wintypes.DWORD)
        a.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

    def _token(self, process_handle):
        token = wintypes.HANDLE()
        self.fixture._check(self.a.OpenProcessToken(
            process_handle, TOKEN_QUERY, ctypes.byref(token),
        ))
        return token

    def _information(self, token, kind):
        required = wintypes.DWORD()
        self.a.GetTokenInformation(token, kind, None, 0, ctypes.byref(required))
        self.assertGreater(required.value, 0)
        storage = ctypes.create_string_buffer(required.value)
        self.fixture._check(self.a.GetTokenInformation(
            token, kind, storage, required.value, ctypes.byref(required),
        ))
        return storage

    def _observed(self, token):
        elevation = self._information(token, TOKEN_ELEVATION)
        elevation_value = ctypes.cast(
            elevation, ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        privileges = self._information(token, TOKEN_PRIVILEGES)
        privilege_count = ctypes.cast(
            privileges, ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        label = self._information(token, TOKEN_INTEGRITY_LEVEL)
        sid = ctypes.cast(
            label, ctypes.POINTER(SID_AND_ATTRIBUTES),
        ).contents.Sid
        self.assertTrue(sid)
        sub_count = self.a.GetSidSubAuthorityCount(sid)[0]
        self.assertGreater(sub_count, 0)
        integrity_rid = self.a.GetSidSubAuthority(sid, sub_count - 1)[0]
        return {
            "integrity_rid": int(integrity_rid),
            "elevated": int(elevation_value),
            "restricted": int(bool(self.a.IsTokenRestricted(token))),
            "privilege_count": int(privilege_count),
        }

    def _close_process_info(self, info):
        if info:
            if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                self.k.TerminateProcess(info.hProcess, 1)
                self.k.WaitForSingleObject(info.hProcess, 5000)
            self.fixture._close(info.hThread)
            self.fixture._close(info.hProcess)

    def test_suspended_worker_token_does_not_gain_integrity_or_privileges(self):
        job = self.fixture._job()
        info = None
        parent_token = None
        worker_token = None
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                info = self.fixture._suspended_python(
                    "from pathlib import Path\n"
                    "import sys,time\n"
                    "Path(sys.argv[1]).joinpath('UNEXPECTED').write_text('BAD')\n"
                    "time.sleep(30)\n",
                    root,
                )
                self.fixture._assert_unstarted(root / "UNEXPECTED", info)
                self.fixture._check(self.k.AssignProcessToJobObject(
                    job, info.hProcess,
                ))
                self.fixture._assert_unstarted(root / "UNEXPECTED", info)
                parent_token = self._token(self.k.GetCurrentProcess())
                worker_token = self._token(info.hProcess)
                parent = self._observed(parent_token)
                child = self._observed(worker_token)
                self.assertEqual(child["integrity_rid"], parent["integrity_rid"])
                self.assertEqual(child["elevated"], parent["elevated"])
                self.assertEqual(child["restricted"], parent["restricted"])
                self.assertEqual(
                    child["privilege_count"], parent["privilege_count"],
                )
                self.assertFalse((root / "UNEXPECTED").exists())
                # A normal suspended worker inherits its creator's token context:
                # equality is NOT equivalent to an enforced restricted token.
                self.fixture._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA05Y_TOKEN parent_child_same_integrity=true "
                    "same_elevation=true same_restricted_state=true "
                    "same_privilege_count=true worker_not_resumed=true "
                    "authorization=DENY"
                )
                print(
                    "WNRA05Y_OBSERVATION integrity_rid="
                    + str(child["integrity_rid"])
                    + " privilege_count=" + str(child["privilege_count"])
                    + " elevated=" + str(child["elevated"])
                    + " restricted=" + str(child["restricted"])
                    + " authorization=DENY"
                )
        finally:
            if worker_token:
                self.fixture._close(worker_token)
            if parent_token:
                self.fixture._close(parent_token)
            if job:
                self.fixture._close(job)
            self._close_process_info(info)

    def test_stronger_integrity_requirement_fails_closed_before_resume(self):
        # Deliberate policy that this launcher does not implement:
        # require the child to have a strictly lower integrity RID.
        job = self.fixture._job()
        info = None
        parent_token = None
        worker_token = None
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                marker = root / "execution_forbidden"
                info = self.fixture._suspended_python(
                    "from pathlib import Path\n"
                    "import sys,time\n"
                    "Path(sys.argv[1]).joinpath('execution_forbidden').write_text('BAD')\n"
                    "time.sleep(30)\n",
                    root,
                )
                self.fixture._check(self.k.AssignProcessToJobObject(
                    job, info.hProcess,
                ))
                self.fixture._assert_unstarted(marker, info)
                parent_token = self._token(self.k.GetCurrentProcess())
                worker_token = self._token(info.hProcess)
                parent_rid = self._observed(parent_token)["integrity_rid"]
                worker_rid = self._observed(worker_token)["integrity_rid"]
                allowed = worker_rid < parent_rid
                self.assertFalse(
                    allowed, "test unexpectedly received stronger token isolation",
                )
                # DENY: abort without ResumeThread, the marker must remain absent.
                self.fixture._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                self.assertFalse(marker.exists())
                print(
                    "WNRA05Y_POLICY lower_integrity_required=true "
                    "lower_integrity_present=false resume_denied=true "
                    "worker_never_executed=true authorization=DENY"
                )
        finally:
            if worker_token:
                self.fixture._close(worker_token)
            if parent_token:
                self.fixture._close(parent_token)
            if job:
                self.fixture._close(job)
            self._close_process_info(info)


if __name__ == "__main__":
    unittest.main()
