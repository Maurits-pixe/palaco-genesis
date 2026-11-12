"""WNRA-05S: Windows Job Object limits in an isolated local test, never production."""
import ctypes
from ctypes import wintypes
import subprocess
import sys
import unittest

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
PROCESS_SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
JOB_MEMORY_BYTES = 96 * 1024 * 1024

class LARGE_INTEGER(ctypes.Structure):
    _fields_ = [("QuadPart", ctypes.c_int64)]

class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", LARGE_INTEGER),
        ("PerJobUserTimeLimit", LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]

@unittest.skipUnless(sys.platform == "win32", "native Windows Job Objects required")
class WindowsJobObjectFixtureTests(unittest.TestCase):
    def setUp(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
        )
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        )
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL

    def _check(self, success):
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def _job(self):
        job = self.kernel.CreateJobObjectW(None, None)
        self._check(job)
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.ProcessMemoryLimit = JOB_MEMORY_BYTES
        try:
            self._check(self.kernel.SetInformationJobObject(
                job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits), ctypes.sizeof(limits)
            ))
            observed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            returned = wintypes.DWORD()
            self._check(self.kernel.QueryInformationJobObject(
                job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(observed), ctypes.sizeof(observed), ctypes.byref(returned)
            ))
            self.assertEqual(observed.ProcessMemoryLimit, JOB_MEMORY_BYTES)
            self.assertTrue(
                observed.BasicLimitInformation.LimitFlags &
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            self.assertTrue(
                observed.BasicLimitInformation.LimitFlags &
                JOB_OBJECT_LIMIT_PROCESS_MEMORY
            )
            return job
        except BaseException:
            self.kernel.CloseHandle(job)
            raise

    def test_job_close_terminates_child_and_descendant(self):
        # Parent waits for GO; assign it to the job BEFORE it starts descendant.
        worker = (
            "import subprocess,sys,time\n"
            "if sys.stdin.readline().strip()!='GO': sys.exit(7)\n"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "print(p.pid,flush=True)\n"
            "time.sleep(30)\n"
        )
        job = self._job()
        process = None
        descendant_handle = None
        try:
            process = subprocess.Popen(
                [sys.executable, "-u", "-c", worker],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            self._check(self.kernel.AssignProcessToJobObject(job, process._handle))
            process.stdin.write("GO\n")
            process.stdin.flush()
            pid_text = process.stdout.readline().strip()
            self.assertTrue(pid_text.isdecimal(), msg=pid_text)
            descendant_handle = self.kernel.OpenProcess(
                PROCESS_SYNCHRONIZE, False, int(pid_text)
            )
            self._check(descendant_handle)
            self.assertEqual(
                self.kernel.WaitForSingleObject(descendant_handle, 0), WAIT_TIMEOUT
            )
            self._check(self.kernel.CloseHandle(job))
            job = None
            self.assertEqual(
                self.kernel.WaitForSingleObject(descendant_handle, 5000),
                WAIT_OBJECT_0
            )
            self.assertEqual(
                self.kernel.WaitForSingleObject(process._handle, 5000),
                WAIT_OBJECT_0
            )
            process.wait(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            print("WNRA05S_JOB_TREE descendant_terminated=true parent_terminated=true authorization=DENY")
        finally:
            if job:
                self.kernel.CloseHandle(job)
            if descendant_handle:
                self.kernel.CloseHandle(descendant_handle)
            if process:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_process_memory_limit_blocks_large_allocation(self):
        worker = (
            "import sys\n"
            "if sys.stdin.readline().strip()!='GO':sys.exit(7)\n"
            "try:\n"
            " data=bytearray(160*1024*1024)\n"
            " data[0]=1;data[-1]=1\n"
            " print('UNEXPECTED_ALLOCATED',flush=True)\n"
            "except MemoryError:\n"
            " print('MEMORY_BLOCKED',flush=True)\n"
        )
        job = self._job()
        process = None
        try:
            process = subprocess.Popen(
                [sys.executable, "-u", "-c", worker],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            self._check(self.kernel.AssignProcessToJobObject(job, process._handle))
            output, errors = process.communicate(input="GO\n", timeout=15)
            self.assertNotIn("UNEXPECTED_ALLOCATED", output)
            self.assertIn("MEMORY_BLOCKED", output, msg=errors[-1000:])
            print("WNRA05S_JOB_MEMORY process_limit_bytes="
                  + str(JOB_MEMORY_BYTES) + " allocation_blocked=true authorization=DENY")
        finally:
            if job:
                self.kernel.CloseHandle(job)
            if process:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

if __name__ == "__main__":
    unittest.main()
