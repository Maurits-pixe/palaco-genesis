"""WNRA-06I — process and object access evidence correlation, Windows only.

Observes the same image in low-only and restricted-SID workers alongside
actual read/execute opens under an impersonated restricted token. Correlation
is NOT a trace of the failing process's loader, nor causal attribution.
"""
import pathlib
import sys
import unittest

from test_windows_anchor_process_bound_failure import (
    ProcessBoundFailureEvidenceTests,
)
from test_windows_anchor_restricted_sid_object_open import (
    RestrictedSidObjectOpenTests,
    FILE_GENERIC_READ, FILE_GENERIC_EXECUTE,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID


@unittest.skipUnless(sys.platform == "win32", "native Windows process required")
class ProcessObjectCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.process = ProcessBoundFailureEvidenceTests(
            "test_process_bound_policy_comparison"
        )
        self.process.setUp()
        self.object = RestrictedSidObjectOpenTests(
            "test_actual_read_and_execute_opens_match_recorded_dacl_probes"
        )
        self.object.setUp()

    def test_process_results_correlate_without_claiming_loader_cause(self):
        executable = pathlib.Path(sys.executable)
        self.assertTrue(executable.is_file())
        source = self.process.fx._source()
        try:
            control = self.process._run(source, "low_only", executable)
            self.assertEqual(control, "worker_live")
            outcomes = {}
            for variant in ("user", "builtin_users"):
                process_outcome = self.process._run(
                    source, variant, executable,
                )
                token = None
                try:
                    token = self.object.fixture._token(source, variant)
                    self.object.fx.token_fixture._lower_integrity(token)
                    observed = self.object.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    reads, read_error = self.object._object_open(
                        token, executable, FILE_GENERIC_READ,
                    )
                    executes, execute_error = self.object._object_open(
                        token, executable, FILE_GENERIC_EXECUTE,
                    )
                    for allowed, error in (
                        (reads, read_error), (executes, execute_error),
                    ):
                        if allowed:
                            self.assertEqual(error, 0)
                        else:
                            self.assertNotEqual(error, 0)
                    outcomes[variant] = process_outcome
                    print(
                        "WNRA06I_CORRELATION variant=" + variant
                        + " control=worker_live"
                        + " worker=" + process_outcome
                        + " image=python"
                        + " read_open=" + str(reads).lower()
                        + " read_error=" + str(read_error)
                        + " execute_open=" + str(executes).lower()
                        + " execute_error=" + str(execute_error)
                        + " same_integrity=true"
                        + " loader_access_traced=false"
                        + " cause_attributed=false authorization=DENY"
                    )
                finally:
                    if token:
                        self.object.fx.fx._close(token)
            self.assertEqual(set(outcomes), {"user", "builtin_users"})
            print(
                "WNRA06I_SUMMARY control=worker_live"
                + " user=" + outcomes["user"]
                + " builtin_users=" + outcomes["builtin_users"]
                + " evidence_scope=process_plus_separate_object_opens"
                + " root_cause=UNKNOWN authorization=DENY"
            )
        finally:
            self.process.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
