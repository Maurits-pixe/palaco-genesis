"""WNRA-06L: bounded process-specific Windows Toolhelp module snapshots.

Read-only Toolhelp snapshots of launched test workers. Absence of a module,
a failed snapshot, or a post-resume early exit is NOT a captured loader denial.
No global ETW, audit policy, ACL or production rights changes.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import subprocess
import sys
import time
import unittest

from test_windows_anchor_process_bound_failure import (
    ProcessBoundFailureEvidenceTests as _ProcessFixture,
)
from test_windows_anchor_suspended_job_launch import (
    CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    RESUME_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID
from test_windows_anchor_low_token_job_launch import (
    ERROR_ACCESS_DENIED, ERROR_BAD_TOKEN_TYPE, ERROR_PRIVILEGE_NOT_HELD,
)
from test_windows_anchor_restricted_sid_access_diagnostics import (
    ERROR_BAD_IMPERSONATION_LEVEL,
)

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
ERROR_BAD_LENGTH = 24
ERROR_PARTIAL_COPY = 299
ERROR_INVALID_PARAMETER = 87
ERROR_NO_MORE_FILES = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


@unittest.skipUnless(sys.platform == "win32", "Windows Toolhelp required")
class ProcessModuleSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.controller = _ProcessFixture("test_process_bound_policy_comparison")
        self.controller.setUp()
        self.k = self.controller.k
        self.fx = self.controller.fx
        self.a = self.controller.a
        self.k.CreateToolhelp32Snapshot.argtypes = (
            wintypes.DWORD, wintypes.DWORD,
        )
        self.k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.k.Module32FirstW.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W),
        )
        self.k.Module32FirstW.restype = wintypes.BOOL
        self.k.Module32NextW.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W),
        )
        self.k.Module32NextW.restype = wintypes.BOOL

    def _modules(self, pid):
        # Distinguish an unavailable snapshot from a valid empty snapshot.
        snapshot = None
        for attempt in range(3):
            ctypes.set_last_error(0)
            handle = self.k.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid,
            )
            if handle != INVALID_HANDLE_VALUE and handle is not None:
                snapshot = handle
                break
            error = ctypes.get_last_error()
            if error == ERROR_BAD_LENGTH and attempt < 2:
                continue
            if error in (
                ERROR_BAD_LENGTH, ERROR_PARTIAL_COPY,
                ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
            ):
                return "unavailable", 0, error
            self.fail("unexpected Toolhelp snapshot Win32 error: " + str(error))
        if snapshot is None:
            return "unavailable", 0, ERROR_BAD_LENGTH
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ctypes.set_last_error(0)
            if not self.k.Module32FirstW(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error in (
                    ERROR_NO_MORE_FILES, ERROR_PARTIAL_COPY,
                    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
                ):
                    return "unavailable", 0, error
                self.fail("unexpected Toolhelp first-module error: " + str(error))
            count = 0
            while True:
                self.assertEqual(entry.th32ProcessID, pid)
                self.assertTrue(entry.szModule)
                count += 1
                self.assertLessEqual(count, 1024, "unbounded module enumeration")
                entry.dwSize = ctypes.sizeof(entry)
                ctypes.set_last_error(0)
                if not self.k.Module32NextW(snapshot, ctypes.byref(entry)):
                    error = ctypes.get_last_error()
                    if error != ERROR_NO_MORE_FILES:
                        self.fail("unexpected Toolhelp next-module error: " + str(error))
                    break
            return "observed", count, 0
        finally:
            self.fx.fx._close(snapshot)

    def _early_samples(self, pid, process_handle):
        """Bounded post-resume observations; no global tracing or privileges."""
        begin = time.perf_counter()
        observations = []
        for index in range(12):
            state = self.k.WaitForSingleObject(process_handle, 0)
            self.assertIn(state, (WAIT_OBJECT_0, WAIT_TIMEOUT))
            elapsed_ms = round((time.perf_counter() - begin) * 1000, 3)
            if state == WAIT_OBJECT_0:
                observations.append(("exited", 0, 0, elapsed_ms))
                break
            status, count, error = self._modules(pid)
            observations.append((status, count, error, elapsed_ms))
            # Bound both the sampling rate and total attempts. WaitForSingleObject
            # also permits early exit observation without busy polling.
            if self.k.WaitForSingleObject(process_handle, 10) == WAIT_OBJECT_0:
                elapsed_ms = round((time.perf_counter() - begin) * 1000, 3)
                observations.append(("exited", 0, 0, elapsed_ms))
                break
        self.assertTrue(observations)
        self.assertLessEqual(len(observations), 13)
        return observations

    def _run_policy(self, source, policy, image, early_capture=False):
        token = None
        job = None
        info = PROCESS_INFORMATION()
        try:
            if policy == "low_only":
                token = self.fx.token_fixture._restricted(source)
            else:
                token = self.controller.probe._token(source, policy)
            self.fx.token_fixture._lower_integrity(token)
            expected_restricted = 0 if policy == "low_only" else 1
            token_status = self.fx.audit._observed(token)
            self.assertEqual(token_status["integrity_rid"], LOW_INTEGRITY_RID)
            self.assertEqual(token_status["restricted"], expected_restricted)
            job = self.fx.fx._job()
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline([
                str(image), "-u", "-c", "import time;time.sleep(30)",
            ]))
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            ctypes.set_last_error(0)
            created = bool(self.a.CreateProcessAsUserW(
                token, str(image), command, None, None, False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
                ctypes.byref(startup), ctypes.byref(info),
            ))
            if not created:
                error = ctypes.get_last_error()
                self.assertIn(
                    error, (ERROR_ACCESS_DENIED, ERROR_BAD_TOKEN_TYPE,
                            ERROR_PRIVILEGE_NOT_HELD, ERROR_BAD_IMPERSONATION_LEVEL),
                )
                self.assertFalse(info.hProcess)
                self.assertFalse(info.hThread)
                self.assertNotEqual(policy, "low_only")
                print(
                    "WNRA06L_WORKER policy=" + policy
                    + " outcome=create_blocked winerror=" + str(error)
                    + " process_bound=false snapshot=not_attempted"
                    + " loader_denial_traced=false authorization=DENY"
                )
                return "create_blocked"
            self.assertTrue(info.hProcess)
            self.assertTrue(info.hThread)
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
            )
            pid = self.k.GetProcessId(info.hProcess)
            self.assertGreater(pid, 0)
            self.assertEqual(pid, info.dwProcessId)
            self.fx.fx._check(
                self.k.AssignProcessToJobObject(job, info.hProcess),
            )
            member = wintypes.BOOL()
            self.fx.fx._check(self.k.IsProcessInJob(
                info.hProcess, job, ctypes.byref(member),
            ))
            self.assertTrue(member.value)
            image_capacity = wintypes.DWORD(32768)
            actual_image = ctypes.create_unicode_buffer(image_capacity.value)
            self.fx.fx._check(self.k.QueryFullProcessImageNameW(
                info.hProcess, 0, actual_image, ctypes.byref(image_capacity),
            ))
            self.assertEqual(
                os.path.normcase(os.path.abspath(actual_image.value)),
                os.path.normcase(os.path.abspath(str(image))),
            )
            child_token = None
            try:
                child_token = self.fx.audit._token(info.hProcess)
                child_observed = self.fx.audit._observed(child_token)
                self.assertEqual(
                    child_observed["integrity_rid"], LOW_INTEGRITY_RID,
                )
                self.assertEqual(
                    child_observed["restricted"], expected_restricted,
                )
            finally:
                if child_token:
                    self.fx.fx._close(child_token)
            before, before_count, before_error = self._modules(pid)
            self.assertNotEqual(
                self.k.ResumeThread(info.hThread), RESUME_FAILED,
            )
            early = self._early_samples(pid, info.hProcess) if early_capture else []
            time.sleep(0.4)
            after, after_count, after_error = self._modules(pid)
            state = self.k.WaitForSingleObject(info.hProcess, 0)
            if state == WAIT_OBJECT_0:
                code = wintypes.DWORD()
                self.fx.fx._check(self.k.GetExitCodeProcess(
                    info.hProcess, ctypes.byref(code),
                ))
                self.assertNotEqual(code.value, 0)
                outcome = "runtime_blocked"
                exit_code = code.value
            else:
                self.assertEqual(state, WAIT_TIMEOUT)
                outcome = "worker_live"
                exit_code = 0
            if policy == "low_only":
                self.assertEqual(outcome, "worker_live")
                self.assertEqual(after, "observed")
                self.assertGreater(after_count, 0)
            if early_capture:
                first_observed = next(
                    (entry for entry in early if entry[0] == "observed"), None,
                )
                first_exit = next(
                    (entry for entry in early if entry[0] == "exited"), None,
                )
                print(
                    "WNRA06M_EARLY policy=" + policy
                    + " samples=" + str(len(early))
                    + " observed_samples=" + str(sum(
                        1 for entry in early if entry[0] == "observed"
                    ))
                    + " first_observed_ms=" + (
                        str(first_observed[3]) if first_observed else "none"
                    )
                    + " first_exit_ms=" + (
                        str(first_exit[3]) if first_exit else "not_observed"
                    )
                    + " max_module_count=" + str(max(
                        (entry[1] for entry in early), default=0,
                    ))
                    + " early_unavailable_codes=" + ",".join(
                        str(code) for code in sorted(set(
                            entry[2] for entry in early
                            if entry[0] == "unavailable"
                        ))
                    )
                    + " final_outcome=" + outcome
                    + " final_exit_code=" + str(exit_code)
                    + " loader_denial_traced=false"
                    + " cause_attributed=false authorization=DENY"
                )
            self.fx.fx._close(job)
            job = None
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 5000),
                WAIT_OBJECT_0,
            )
            print(
                "WNRA06L_WORKER policy=" + policy
                + " outcome=" + outcome
                + " pid_verified=true image_verified=true"
                + " integrity=4096 restricted="
                + str(bool(expected_restricted)).lower()
                + " snapshot_before=" + before
                + " before_count=" + str(before_count)
                + " before_error=" + str(before_error)
                + " snapshot_after=" + after
                + " after_count=" + str(after_count)
                + " after_error=" + str(after_error)
                + " exit_code=" + str(exit_code)
                + " loader_denial_traced=false"
                + " cause_attributed=false authorization=DENY"
            )
            return outcome
        finally:
            if job:
                self.fx.fx._close(job)
            if info.hProcess:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self.fx.fx._close(info.hProcess)
            if info.hThread:
                self.fx.fx._close(info.hThread)
            if token:
                self.fx.fx._close(token)

    def test_bounded_process_bound_module_snapshots(self):
        image = pathlib.Path(sys.executable)
        self.assertTrue(image.is_file())
        source = self.fx._source()
        try:
            control = self._run_policy(source, "low_only", image)
            user = self._run_policy(source, "user", image)
            users = self._run_policy(source, "builtin_users", image)
            self.assertEqual(control, "worker_live")
            self.assertIn(user, ("create_blocked", "runtime_blocked", "worker_live"))
            self.assertIn(users, ("create_blocked", "runtime_blocked", "worker_live"))
            print(
                "WNRA06L_SUMMARY control=" + control
                + " user=" + user
                + " builtin_users=" + users
                + " evidence=process_specific_module_snapshots"
                + " loader_denial_traced=false"
                + " root_cause=UNKNOWN authorization=DENY"
            )
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
