"""Native readiness evidence inventory regression tests (no real hardware)."""
from dataclasses import replace
import json
import unittest

from native_platform_readiness import (
    NativeCapabilityEvidence, NativeEvidenceStatus, REQUIRED_CHECKS,
    inspect_native_readiness,
)
from platform_checkpoint_bridge import NativePlatform, NativeStorageIdentity
from protocol import TransferError

NS = b"w" * 32
DEV = b"d" * 32


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.identity = NativeStorageIdentity(
            NativePlatform.WINDOWS_TPM, NS, DEV, 1,
        )
        self.status = {name: NativeEvidenceStatus.MISSING for name in REQUIRED_CHECKS}
        self.refs = {name: "" for name in REQUIRED_CHECKS}

    def inspect(self):
        evidence = NativeCapabilityEvidence(
            self.identity, dict(self.status), dict(self.refs),
        )
        return json.loads(inspect_native_readiness(
            evidence, self.identity, self.identity.platform,
        ).canonical_json)

    def verify_all_claims(self):
        for name in REQUIRED_CHECKS:
            self.status[name] = NativeEvidenceStatus.VERIFIED
            self.refs[name] = "reviewed:" + name

    def test_missing_checks_hold(self):
        data = self.inspect()
        self.assertFalse(data["evidence_complete_claimed"])
        self.assertEqual((data["decision"], data["authorization"]), ("HOLD", "DENY"))

    def test_complete_claims_still_hold(self):
        self.verify_all_claims()
        data = self.inspect()
        self.assertTrue(data["evidence_complete_claimed"])
        self.assertEqual(data["decision"], "HOLD")
        self.assertFalse(data["hardware_verified_by_this_module"])
        self.assertFalse(data["origin_authenticated"])

    def test_windows_platform_recorded(self):
        self.assertEqual(self.inspect()["platform"], "windows_tpm")

    def test_android_platform_recorded(self):
        self.identity = replace(
            self.identity, platform=NativePlatform.ANDROID_KEYMINT,
        )
        self.assertEqual(self.inspect()["platform"], "android_keymint")

    def test_missing_device_hardware_binding(self):
        self.verify_all_claims()
        self.status["device_hardware_binding"] = NativeEvidenceStatus.MISSING
        self.refs["device_hardware_binding"] = ""
        self.assertFalse(self.inspect()["evidence_complete_claimed"])

    def test_failed_monotonic_pin(self):
        self.verify_all_claims()
        self.status["independent_monotonic_pin"] = NativeEvidenceStatus.FAILED
        self.assertFalse(self.inspect()["evidence_complete_claimed"])

    def test_failed_restart_rollback(self):
        self.verify_all_claims()
        self.status["rollback_after_restart"] = NativeEvidenceStatus.FAILED
        self.assertFalse(self.inspect()["evidence_complete_claimed"])

    def test_failed_atomic_cas(self):
        self.verify_all_claims()
        self.status["atomic_compare_and_advance"] = NativeEvidenceStatus.FAILED
        self.assertFalse(self.inspect()["evidence_complete_claimed"])

    def test_failed_nonexportability(self):
        self.verify_all_claims()
        self.status["hardware_key_nonexportability"] = NativeEvidenceStatus.FAILED
        self.assertFalse(self.inspect()["evidence_complete_claimed"])

    def test_required_check_cannot_be_omitted(self):
        self.status.pop("tamper_and_replay_rejection")
        with self.assertRaises(TransferError):
            NativeCapabilityEvidence(self.identity, self.status, self.refs)

    def test_unrecognized_extra_check_rejected(self):
        self.status["user_override"] = NativeEvidenceStatus.VERIFIED
        with self.assertRaises(TransferError):
            NativeCapabilityEvidence(self.identity, self.status, self.refs)

    def test_unknown_status_rejected(self):
        self.status["trust_root_provisioning"] = "verified"
        with self.assertRaises(TransferError):
            NativeCapabilityEvidence(self.identity, self.status, self.refs)

    def test_unreferenced_pass_rejected(self):
        self.status["trust_root_provisioning"] = NativeEvidenceStatus.VERIFIED
        with self.assertRaises(TransferError):
            NativeCapabilityEvidence(self.identity, self.status, self.refs)

    def test_untrusted_markup_reference_rejected(self):
        self.verify_all_claims()
        self.refs["trust_root_provisioning"] = "<script>forged</script>"
        with self.assertRaises(TransferError):
            NativeCapabilityEvidence(self.identity, self.status, self.refs)

    def test_wrong_expected_device_denies_completeness(self):
        self.verify_all_claims()
        ev = NativeCapabilityEvidence(self.identity, self.status, self.refs)
        wrong = replace(self.identity, device_binding=b"x" * 32)
        data = json.loads(inspect_native_readiness(
            ev, wrong, wrong.platform,
        ).canonical_json)
        self.assertFalse(data["identity_matches"])
        self.assertFalse(data["evidence_complete_claimed"])

    def test_cross_platform_expectation_rejected(self):
        ev = NativeCapabilityEvidence(self.identity, self.status, self.refs)
        with self.assertRaises(TransferError):
            inspect_native_readiness(ev, self.identity, NativePlatform.ANDROID_KEYMINT)

    def test_report_fingerprint_deterministic(self):
        ev = NativeCapabilityEvidence(self.identity, self.status, self.refs)
        first = inspect_native_readiness(ev, self.identity, self.identity.platform)
        second = inspect_native_readiness(ev, self.identity, self.identity.platform)
        self.assertEqual(first, second)

    def test_report_fingerprint_changes_with_status(self):
        ev = NativeCapabilityEvidence(self.identity, self.status, self.refs)
        first = inspect_native_readiness(ev, self.identity, self.identity.platform)
        self.status["rollback_after_restart"] = NativeEvidenceStatus.FAILED
        changed = NativeCapabilityEvidence(self.identity, self.status, self.refs)
        second = inspect_native_readiness(changed, self.identity, self.identity.platform)
        self.assertNotEqual(first.sha256, second.sha256)

    def test_no_release_action_exposed(self):
        self.verify_all_claims()
        result = self.inspect()
        self.assertNotIn("release", result)
        self.assertNotIn("enable", result)
        self.assertNotIn("deploy", result)

    def test_report_scope_explicit(self):
        self.assertEqual(self.inspect()["namespace"], NS.hex())
        self.assertEqual(self.inspect()["device_binding"], DEV.hex())


if __name__ == "__main__":
    unittest.main()
