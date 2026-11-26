"""Regression suite for Windows native probe correlation (not TPM tests)."""
from dataclasses import replace
import json
import unittest

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from windows_native_correlation import correlate_windows_probe
from windows_native_intake import WindowsNativeProbe
from windows_native_ipc_contract import WindowsInspectRequest, encode_windows_inspect_request

IDENTITY = NativeStorageIdentity(NativePlatform.WINDOWS_TPM, b"n"*32, b"d"*32, 7)
NONCE = b"c"*32


class WindowsCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.request = WindowsInspectRequest(IDENTITY.namespace, IDENTITY.device_binding,
                                             IDENTITY.generation, NONCE)
        self.probe = WindowsNativeProbe(IDENTITY, NONCE, b"r"*32, "1.0")

    def report(self, request=None, probe=None, identity=IDENTITY, nonce=NONCE):
        frame = encode_windows_inspect_request(request or self.request)
        return json.loads(correlate_windows_probe(
            frame, probe or self.probe, identity, nonce).canonical_json)

    def test_matching_diagnostics_hold(self):
        d = self.report()
        self.assertTrue(d["input_correlated"])
        self.assertEqual((d["decision"], d["authorization"]), ("HOLD", "DENY"))

    def test_never_claims_hardware_authentication(self):
        d = self.report()
        for key in ("ipc_peer_authenticated", "service_identity_authenticated",
                    "tpm_attested", "replay_resistance_verified",
                    "hardware_verified_by_this_module"):
            self.assertFalse(d[key])

    def test_request_namespace_mismatch(self):
        q = replace(self.request, namespace=b"x"*32)
        self.assertFalse(self.report(request=q)["input_correlated"])

    def test_request_device_mismatch(self):
        q = replace(self.request, device_binding=b"x"*32)
        self.assertFalse(self.report(request=q)["input_correlated"])

    def test_request_generation_mismatch(self):
        q = replace(self.request, generation=8)
        self.assertFalse(self.report(request=q)["input_correlated"])

    def test_request_nonce_mismatch(self):
        q = replace(self.request, challenge=b"x"*32)
        self.assertFalse(self.report(request=q)["input_correlated"])

    def test_probe_namespace_mismatch(self):
        p = replace(self.probe, identity=replace(IDENTITY, namespace=b"x"*32))
        self.assertFalse(self.report(probe=p)["input_correlated"])

    def test_probe_device_mismatch(self):
        p = replace(self.probe, identity=replace(IDENTITY, device_binding=b"x"*32))
        self.assertFalse(self.report(probe=p)["input_correlated"])

    def test_probe_generation_mismatch(self):
        p = replace(self.probe, identity=replace(IDENTITY, generation=8))
        self.assertFalse(self.report(probe=p)["input_correlated"])

    def test_probe_nonce_mismatch(self):
        p = replace(self.probe, challenge=b"x"*32)
        self.assertFalse(self.report(probe=p)["input_correlated"])

    def test_zero_response_rejected_as_complete(self):
        p = replace(self.probe, response_digest=bytes(32))
        self.assertFalse(self.report(probe=p)["input_correlated"])

    def test_wrong_expected_namespace(self):
        wrong = replace(IDENTITY, namespace=b"x"*32)
        self.assertFalse(self.report(identity=wrong)["input_correlated"])

    def test_wrong_expected_device(self):
        wrong = replace(IDENTITY, device_binding=b"x"*32)
        self.assertFalse(self.report(identity=wrong)["input_correlated"])

    def test_wrong_expected_generation(self):
        wrong = replace(IDENTITY, generation=8)
        self.assertFalse(self.report(identity=wrong)["input_correlated"])

    def test_wrong_expected_nonce(self):
        self.assertFalse(self.report(nonce=b"x"*32)["input_correlated"])

    def test_android_expected_identity_rejected(self):
        wrong = replace(IDENTITY, platform=NativePlatform.ANDROID_KEYMINT)
        with self.assertRaises(TransferError):
            self.report(identity=wrong)

    def test_malformed_expected_nonce_rejected(self):
        with self.assertRaises(TransferError):
            self.report(nonce=b"short")

    def test_malformed_frame_rejected(self):
        with self.assertRaises(TransferError):
            correlate_windows_probe(b"{}", self.probe, IDENTITY, NONCE)

    def test_deterministic_report(self):
        frame = encode_windows_inspect_request(self.request)
        a = correlate_windows_probe(frame, self.probe, IDENTITY, NONCE)
        b = correlate_windows_probe(frame, self.probe, IDENTITY, NONCE)
        self.assertEqual(a, b)

    def test_report_is_not_unlock_capability(self):
        for key in ("unlock", "import", "write", "deploy", "advance", "release"):
            self.assertNotIn(key, self.report())


if __name__ == "__main__":
    unittest.main()
