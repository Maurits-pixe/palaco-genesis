"""Twenty regression tests for Windows service admission inventory (not OS tests)."""
from dataclasses import replace
import json
import unittest

from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError
from windows_native_intake import WindowsNativeProbe
from windows_native_ipc_contract import WindowsInspectRequest, encode_windows_inspect_request
from windows_service_admission import (
    ControlClaim, REQUIRED_CONTROLS, WindowsServiceReview,
    inspect_windows_service_admission,
)

IDENTITY = NativeStorageIdentity(NativePlatform.WINDOWS_TPM, b"n"*32, b"d"*32, 3)
CHALLENGE = b"c"*32


class ServiceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.frame = encode_windows_inspect_request(
            WindowsInspectRequest(IDENTITY.namespace, IDENTITY.device_binding,
                                  IDENTITY.generation, CHALLENGE))
        self.probe = WindowsNativeProbe(IDENTITY, CHALLENGE, b"r"*32, "0.1")
        self.controls = {key: ControlClaim.NOT_REVIEWED for key in REQUIRED_CONTROLS}
        self.refs = {key: "" for key in REQUIRED_CONTROLS}

    def review(self, identity=IDENTITY):
        return WindowsServiceReview(identity, dict(self.controls), dict(self.refs))

    def inspect(self, frame=None, probe=None, identity=IDENTITY, nonce=CHALLENGE):
        return json.loads(inspect_windows_service_admission(
            self.frame if frame is None else frame,
            self.probe if probe is None else probe,
            self.review(identity), nonce).canonical_json)

    def claim_all(self):
        for key in REQUIRED_CONTROLS:
            self.controls[key] = ControlClaim.EXTERNAL_PASS_CLAIM
            self.refs[key] = "review/" + key

    def test_missing_reviews_hold(self):
        self.assertFalse(self.inspect()["review_complete_claimed"])

    def test_complete_claims_still_deny(self):
        self.claim_all()
        data = self.inspect()
        self.assertTrue(data["review_complete_claimed"])
        self.assertEqual((data["decision"], data["authorization"]), ("HOLD", "DENY"))

    def test_never_claims_native_execution(self):
        self.claim_all()
        d = self.inspect()
        for key in ("windows_service_running", "os_peer_identity_verified",
                    "tpm_attested", "hardware_verified_by_this_module",
                    "ipc_session_opened"):
            self.assertFalse(d[key])

    def test_wrong_device_not_correlated(self):
        p = replace(self.probe, identity=replace(IDENTITY, device_binding=b"x"*32))
        self.assertFalse(self.inspect(probe=p)["input_correlated_claimed"])

    def test_wrong_nonce_not_correlated(self):
        p = replace(self.probe, challenge=b"x"*32)
        self.assertFalse(self.inspect(probe=p)["input_correlated_claimed"])

    def test_wrong_generation_not_correlated(self):
        p = replace(self.probe, identity=replace(IDENTITY, generation=4))
        self.assertFalse(self.inspect(probe=p)["input_correlated_claimed"])

    def test_zero_response_not_correlated(self):
        p = replace(self.probe, response_digest=bytes(32))
        self.assertFalse(self.inspect(probe=p)["input_correlated_claimed"])

    def test_failed_control_prevents_completeness(self):
        self.claim_all()
        self.controls["named_pipe_dacl"] = ControlClaim.FAILED
        self.assertFalse(self.inspect()["review_complete_claimed"])

    def test_not_reviewed_control_prevents_completeness(self):
        self.claim_all()
        self.controls["caller_token_verified"] = ControlClaim.NOT_REVIEWED
        self.assertFalse(self.inspect()["review_complete_claimed"])

    def test_missing_required_control_rejected(self):
        self.controls.pop("service_binary_integrity")
        with self.assertRaises(TransferError):
            self.review()

    def test_extra_control_rejected(self):
        self.controls["allow_all"] = ControlClaim.EXTERNAL_PASS_CLAIM
        self.refs["allow_all"] = "fake"
        with self.assertRaises(TransferError):
            self.review()

    def test_unknown_status_rejected(self):
        self.controls["tpm_trust_root"] = "verified"
        with self.assertRaises(TransferError):
            self.review()

    def test_unreferenced_external_pass_rejected(self):
        self.controls["tpm_trust_root"] = ControlClaim.EXTERNAL_PASS_CLAIM
        with self.assertRaises(TransferError):
            self.review()

    def test_markup_reference_rejected(self):
        self.refs["tpm_trust_root"] = "<script>"
        with self.assertRaises(TransferError):
            self.review()

    def test_overlong_reference_rejected(self):
        self.refs["tpm_trust_root"] = "a"*129
        with self.assertRaises(TransferError):
            self.review()

    def test_android_expected_identity_rejected(self):
        with self.assertRaises(TransferError):
            self.review(replace(IDENTITY, platform=NativePlatform.ANDROID_KEYMINT))

    def test_bad_frame_rejected(self):
        with self.assertRaises(TransferError):
            self.inspect(frame=b"{}")

    def test_bad_challenge_rejected(self):
        with self.assertRaises(TransferError):
            self.inspect(nonce=b"short")

    def test_deterministic_fingerprint(self):
        review = self.review()
        a = inspect_windows_service_admission(self.frame, self.probe, review, CHALLENGE)
        b = inspect_windows_service_admission(self.frame, self.probe, review, CHALLENGE)
        self.assertEqual(a, b)

    def test_never_exposes_permission_tokens(self):
        self.claim_all()
        d = self.inspect()
        for key in ("release", "unlock", "import", "deploy", "execute", "write"):
            self.assertNotIn(key, d)


if __name__ == "__main__":
    unittest.main()
