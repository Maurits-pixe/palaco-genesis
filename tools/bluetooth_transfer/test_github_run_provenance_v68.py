"""v6.8 GitHub API workflow-run provenance comparison: offline fixtures."""
import unittest
from verify_scm_ci_incident import EvidenceRejected
from github_run_provenance_v68 import verify_run_payload

SHA = "a" * 40
HEAD = "b" * 40


class GitHubRunProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "GITHUB_REPOSITORY": "example/palaco",
            "GITHUB_RUN_ID": "12345678",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": SHA,
        }
        self.event = {"pull_request": {"head": {"sha": HEAD}}}
        self.remote = {
            "id": 12345678, "run_attempt": 1, "event": "pull_request",
            "head_sha": HEAD, "repository": {"full_name": "example/palaco"}
        }

    def verify(self):
        return verify_run_payload(self.remote, self.context, self.event)

    def test_legitimate_pull_request(self):
        self.assertEqual(self.verify()["api_head_sha"], HEAD)

    def test_checkout_merge_sha_also_supported(self):
        self.remote["head_sha"] = SHA
        self.verify()

    def test_wrong_run_id_rejected(self):
        self.remote["id"] += 1
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_wrong_attempt_rejected(self):
        self.remote["run_attempt"] += 1
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_wrong_repo_rejected(self):
        self.remote["repository"]["full_name"] = "attacker/palaco"
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_wrong_event_rejected(self):
        self.remote["event"] = "push"
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_unrecognized_head_rejected(self):
        self.remote["head_sha"] = "c"*40
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_missing_pr_head_rejected(self):
        self.event = {}
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_invalid_sha_rejected(self):
        self.remote["head_sha"] = "not-sha"
        with self.assertRaises(EvidenceRejected):
            self.verify()

    def test_push_run(self):
        self.context["GITHUB_EVENT_NAME"] = "push"
        self.remote["event"] = "push"
        self.remote["head_sha"] = SHA
        self.event = {}
        self.verify()

    def test_missing_metadata_rejected(self):
        del self.remote["run_attempt"]
        with self.assertRaises(EvidenceRejected):
            self.verify()


if __name__ == "__main__":
    unittest.main()
