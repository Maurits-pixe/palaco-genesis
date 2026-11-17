"""Candidate v9 ledger regression tests with synthetic trust fixtures."""
import base64
import copy
import unittest

from policy_ledger_v9 import (
    GENESIS, LedgerError, propose_event, replay_ledger,
    verify_anchored_ledger
)


class PolicyLedgerTests(unittest.TestCase):
    def setUp(self):
        key = base64.b64encode(bytes(range(32))).decode("ascii")
        self.before = {
            "schema": "palaco-key-registry/v8", "version": 1,
            "keys": [{"key_id": "fixture-1", "public_key_b64": key,
                      "status": "active", "scopes": ["candidate"]}]
        }
        self.after = copy.deepcopy(self.before)
        self.after["version"] = 2
        self.after["keys"][0]["status"] = "revoked"

    def first(self):
        event, head = propose_event((), self.before, self.after, expected_head=GENESIS)
        return (event,), head

    def test_valid_revoke(self):
        events, head = self.first()
        self.assertEqual(replay_ledger(events), (head, self.after))

    def test_revocation_cannot_reverse(self):
        events, head = self.first()
        restored = copy.deepcopy(self.after)
        restored["version"] = 3
        restored["keys"][0]["status"] = "active"
        with self.assertRaisesRegex(LedgerError, "REVOCATION_TERMINAL"):
            propose_event(events, self.after, restored, expected_head=head)

    def test_scope_change_rejected(self):
        widened = copy.deepcopy(self.after)
        widened["keys"][0]["scopes"] = ["candidate", "another"]
        with self.assertRaisesRegex(LedgerError, "SCOPE_CHANGE_REQUIRES_NEW_KEY"):
            propose_event((), self.before, widened, expected_head=GENESIS)

    def test_key_material_change_rejected(self):
        changed = copy.deepcopy(self.after)
        changed["keys"][0]["public_key_b64"] = base64.b64encode(b"x" * 32).decode()
        with self.assertRaisesRegex(LedgerError, "KEY_MATERIAL_CHANGE_FORBIDDEN"):
            propose_event((), self.before, changed, expected_head=GENESIS)

    def test_key_removal_rejected(self):
        changed = copy.deepcopy(self.after)
        changed["keys"] = [{
            "key_id": "replacement", "public_key_b64": base64.b64encode(b"x" * 32).decode(),
            "status": "active", "scopes": ["candidate"]
        }]
        with self.assertRaisesRegex(LedgerError, "KEY_REMOVAL_FORBIDDEN"):
            propose_event((), self.before, changed, expected_head=GENESIS)

    def test_version_skip_rejected(self):
        changed = copy.deepcopy(self.after)
        changed["version"] = 4
        with self.assertRaisesRegex(LedgerError, "INVALID_REGISTRY_VERSION"):
            propose_event((), self.before, changed, expected_head=GENESIS)

    def test_stale_head_rejected(self):
        with self.assertRaisesRegex(LedgerError, "STALE_CHECKPOINT"):
            propose_event((), self.before, self.after, expected_head="0" * 64)

    def test_modified_event_rejected(self):
        events, _ = self.first()
        altered = copy.deepcopy(events[0])
        altered["after"]["keys"][0]["status"] = "active"
        with self.assertRaisesRegex(LedgerError, "SNAPSHOT_DIGEST_MISMATCH"):
            replay_ledger((altered,))

    def test_broken_predecessor_rejected(self):
        events, _ = self.first()
        altered = dict(events[0], previous="0" * 64)
        with self.assertRaisesRegex(LedgerError, "BROKEN_LEDGER_CHAIN"):
            replay_ledger((altered,))

    def test_wrong_sequence_rejected(self):
        events, _ = self.first()
        altered = dict(events[0], sequence=3)
        with self.assertRaisesRegex(LedgerError, "BROKEN_LEDGER_CHAIN"):
            replay_ledger((altered,))

    def test_extra_authority_field_rejected(self):
        events, _ = self.first()
        altered = dict(events[0], authorized=True)
        with self.assertRaisesRegex(LedgerError, "INVALID_EVENT"):
            replay_ledger((altered,))

    def test_cross_event_discontinuity_rejected(self):
        events, head = self.first()
        later = copy.deepcopy(self.after)
        later["version"] = 3
        later["keys"].append({
            "key_id": "fixture-2",
            "public_key_b64": base64.b64encode(b"a" * 32).decode(),
            "status": "active", "scopes": ["candidate"]
        })
        second, _ = propose_event(events, self.after, later, expected_head=head)
        altered = copy.deepcopy(second)
        altered["before"]["keys"][0]["status"] = "active"
        from key_registry_v8 import snapshot_digest
        altered["before_sha256"] = snapshot_digest(altered["before"])
        from policy_ledger_v9 import event_digest
        self.assertNotEqual(event_digest(altered), event_digest(second))
        with self.assertRaisesRegex(LedgerError, "DISCONTINUOUS_REGISTRY_HISTORY"):
            replay_ledger(events + (altered,))

    def test_anchored_fixture_never_authorizes(self):
        events, head = self.first()
        report = verify_anchored_ledger(
            events, get_trusted_anchor=lambda: (1, head),
            verify_policy=lambda *_: True)
        self.assertEqual(report["authorization"], "DENY")
        self.assertEqual(report["release"], "HOLD")
        self.assertIs(report["production_release_enabled"], False)

    def test_missing_external_anchor(self):
        events, _ = self.first()
        with self.assertRaisesRegex(LedgerError, "EXTERNAL_TRUST_REQUIRED"):
            verify_anchored_ledger(events, get_trusted_anchor=None,
                                   verify_policy=lambda *_: True)

    def test_rollback_anchor(self):
        events, _ = self.first()
        with self.assertRaisesRegex(LedgerError, "ANCHOR_MISMATCH"):
            verify_anchored_ledger(events, get_trusted_anchor=lambda: (0, GENESIS),
                                   verify_policy=lambda *_: True)

    def test_nonboolean_external_policy(self):
        events, head = self.first()
        with self.assertRaisesRegex(LedgerError, "POLICY_UNVERIFIED"):
            verify_anchored_ledger(events, get_trusted_anchor=lambda: (1, head),
                                   verify_policy=lambda *_: 1)

    def test_policy_unavailable(self):
        events, head = self.first()
        def inaccessible(*_):
            raise ConnectionError("offline")
        with self.assertRaisesRegex(LedgerError, "EXTERNAL_TRUST_UNAVAILABLE"):
            verify_anchored_ledger(events, get_trusted_anchor=lambda: (1, head),
                                   verify_policy=inaccessible)

    def test_proposal_is_frozen(self):
        event, _ = propose_event((), self.before, self.after, expected_head=GENESIS)
        self.after["keys"][0]["status"] = "active"
        self.assertEqual(event["after"]["keys"][0]["status"], "revoked")

    def test_boolean_sequence_rejected(self):
        events, _ = self.first()
        altered = dict(events[0], sequence=True)
        with self.assertRaisesRegex(LedgerError, "INVALID_SEQUENCE"):
            replay_ledger((altered,))


if __name__ == "__main__":
    unittest.main()
