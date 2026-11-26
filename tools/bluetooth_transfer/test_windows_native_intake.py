"""Regression checks for untrusted Windows native diagnostic intake."""
from dataclasses import replace
import json
import unittest

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from windows_native_intake import WindowsNativeProbe, inspect_windows_native_probe

IDENTITY = NativeStorageIdentity(NativePlatform.WINDOWS_TPM, b"n"*32, b"d"*32, 1)
NONCE = b"c"*32


class WindowsNativeIntakeTests(unittest.TestCase):
    def probe(self):
        return WindowsNativeProbe(IDENTITY, NONCE, b"r"*32, "0.1-diagnostic")

    def inspect(self, probe=None, identity=IDENTITY, nonce=NONCE):
        result = inspect_windows_native_probe(probe or self.probe(), identity, nonce)
        return json.loads(result.canonical_json)

    def test_matching_claims_never_authorize(self):
        d = self.inspect()
        self.assertTrue(d["identity_matches_claimed"])
        self.assertTrue(d["challenge_matches_claimed"])
        self.assertEqual((d["decision"], d["authorization"]), ("HOLD", "DENY"))

    def test_never_claims_tpm_attestation(self):
        d = self.inspect()
        self.assertFalse(d["tpm_attested"])
        self.assertFalse(d["rollback_resistant"])
        self.assertFalse(d["origin_authenticated"])
        self.assertFalse(d["hardware_verified_by_this_module"])

    def test_mismatched_challenge(self):
        self.assertFalse(self.inspect(nonce=b"x"*32)["challenge_matches_claimed"])

    def test_wrong_device(self):
        wrong = replace(IDENTITY, device_binding=b"x"*32)
        self.assertFalse(self.inspect(identity=wrong)["identity_matches_claimed"])

    def test_wrong_generation(self):
        wrong = replace(IDENTITY, generation=2)
        self.assertFalse(self.inspect(identity=wrong)["identity_matches_claimed"])

    def test_wrong_namespace(self):
        wrong = replace(IDENTITY, namespace=b"x"*32)
        self.assertFalse(self.inspect(identity=wrong)["identity_matches_claimed"])

    def test_android_rejected(self):
        wrong = replace(IDENTITY, platform=NativePlatform.ANDROID_KEYMINT)
        with self.assertRaises(TransferError):
            self.inspect(identity=wrong)

    def test_android_probe_rejected(self):
        with self.assertRaises(TransferError):
            WindowsNativeProbe(replace(IDENTITY, platform=NativePlatform.ANDROID_KEYMINT),
                               NONCE, b"r"*32, "1")

    def test_short_nonce_rejected(self):
        with self.assertRaises(TransferError):
            WindowsNativeProbe(IDENTITY, b"a", b"r"*32, "1")

    def test_short_response_rejected(self):
        with self.assertRaises(TransferError):
            WindowsNativeProbe(IDENTITY, NONCE, b"r", "1")

    def test_untrusted_service_version_markup_rejected(self):
        with self.assertRaises(TransferError):
            WindowsNativeProbe(IDENTITY, NONCE, b"r"*32, "<script>")

    def test_bad_expected_nonce_rejected(self):
        with self.assertRaises(TransferError):
            self.inspect(nonce=b"x")

    def test_type_confusion_rejected(self):
        with self.assertRaises(TransferError):
            self.inspect(probe="pretend-trusted")

    def test_zero_response_still_hold(self):
        p = replace(self.probe(), response_digest=bytes(32))
        d = self.inspect(probe=p)
        self.assertFalse(d["response_digest_present"])
        self.assertEqual(d["decision"], "HOLD")

    def test_report_deterministic(self):
        p = self.probe()
        self.assertEqual(inspect_windows_native_probe(p, IDENTITY, NONCE),
                         inspect_windows_native_probe(p, IDENTITY, NONCE))

    def test_no_mutation_capability(self):
        d = self.inspect()
        for key in ("unlock", "import", "deploy", "authorize", "advance", "write"):
            self.assertNotIn(key, d)


if __name__ == "__main__":
    unittest.main()
