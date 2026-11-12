"""WNRA-05T: Windows-only suspended process -> Job Object assignment fixture.

No production launcher, privilege boundary, independent authority or release gate.
"""
import ctypes
from ctypes import wintypes
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from test_windows_anchor_job_objects import (
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
)

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
RESUME_FAILED = 0xFFFFFFFF
PROCESS_SYNCHRONIZE = 0x00100000

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

@unittest.skipUnless(sys.platform == "win32", "Windows native Job Object required")
class SuspendedJobLaunchTests(unittest.TestCase):
    def setUp(self):
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k = k
        k.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.SetInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        )
        k.SetInformationJobObject.restype = wintypes.BOOL
        k.CreateProcessW.argtypes = (
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
            wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        )
        k.CreateProcessW.restype = wintypes.BOOL
        k.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.ResumeThread.argtypes = (wintypes.HANDLE,)
        k.ResumeThread.restype = wintypes.DWORD
        k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.OpenProcess.restype = wintypes.HANDLE
        k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.TerminateProcess.restype = wintypes.BOOL
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.CloseHandle.restype = wintypes.BOOL

    def _check(self, success):
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def _job(self):
        job = self.k.CreateJobObjectW(None, None)
        self._check(job)
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            self._check(self.k.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits),
            ))
        except BaseException:
            self.k.CloseHandle(job)
            raise
        return job

    def _suspended_python(self, script, directory):
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        info = PROCESS_INFORMATION()
        # list2cmdline is Windows-specific; mutable buffer is required by CreateProcessW.
        command = subprocess.list2cmdline([
            sys.executable, "-u", "-c", script, str(directory),
        ])
        command_buffer = ctypes.create_unicode_buffer(command)
        self._check(self.k.CreateProcessW(
            sys.executable, command_buffer, None, None, False,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None, None, ctypes.byref(startup), ctypes.byref(info),
        ))
        return info

    def _close(self, handle):
        if handle:
            self._check(self.k.CloseHandle(handle))

    def _assert_unstarted(self, marker, info):
        self.assertFalse(marker.exists(), "suspended worker executed before resume")
        self.assertEqual(
            self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
        )

    def test_assign_before_resume_and_close_job_kills_descendant(self):
        script = (
            "from pathlib import Path\n"
            "import subprocess,sys,time\n"
            "root=Path(sys.argv[1])\n"
            "(root/'started').write_text('started',encoding='utf-8')\n"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL)\n"
            "(root/'descendant_pid').write_text(str(child.pid),encoding='ascii')\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            job = self._job()
            info = None
            descendant = None
            try:
                info = self._suspended_python(script, root)
                self._assert_unstarted(root / "started", info)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "started", info)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                deadline = time.monotonic() + 12
                while not (root / "descendant_pid").exists():
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_OBJECT_0:
                        self.fail("worker exited before descendant marker")
                    if time.monotonic() >= deadline:
                        self.fail("descendant marker timed out")
                    time.sleep(0.025)
                self.assertTrue((root / "started").exists())
                pid_text = (root / "descendant_pid").read_text(encoding="ascii")
                self.assertTrue(pid_text.isdecimal(), pid_text)
                descendant = self.k.OpenProcess(
                    PROCESS_SYNCHRONIZE, False, int(pid_text),
                )
                self._check(descendant)
                self.assertEqual(
                    self.k.WaitForSingleObject(descendant, 0), WAIT_TIMEOUT,
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
                )
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(descendant, 5000), WAIT_OBJECT_0,
                )
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000), WAIT_OBJECT_0,
                )
                print(
                    "WNRA05T_SUSPENDED assign_before_resume=true "
                    "descendant_terminated=true authorization=DENY"
                )
            finally:
                if job:
                    self._close(job)
                if info:
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                        self.k.TerminateProcess(info.hProcess, 1)
                        self.k.WaitForSingleObject(info.hProcess, 5000)
                    self._close(info.hThread)
                    self._close(info.hProcess)
                if descendant:
                    self._close(descendant)

    def test_abort_before_resume_never_runs_worker(self):
        script = (
            "from pathlib import Path\n"
            "import sys,time\n"
            "Path(sys.argv[1]).joinpath('unexpected').write_text('BAD')\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            job = self._job()
            info = None
            try:
                info = self._suspended_python(script, root)
                self._check(self.k.AssignProcessToJobObject(job, info.hProcess))
                self._assert_unstarted(root / "unexpected", info)
                # Abort path: never resume. Closing the last job handle terminates it.
                self._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000), WAIT_OBJECT_0,
                )
                self.assertFalse((root / "unexpected").exists())
                print(
                    "WNRA05T_ABORT no_resume=true worker_never_executed=true "
                    "authorization=DENY"
                )
            finally:
                if job:
                    self._close(job)
                if info:
                    if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                        self.k.TerminateProcess(info.hProcess, 1)
                        self.k.WaitForSingleObject(info.hProcess, 5000)
                    self._close(info.hThread)
                    self._close(info.hProcess)


if __name__ == "__main__":
    unittest.main()
