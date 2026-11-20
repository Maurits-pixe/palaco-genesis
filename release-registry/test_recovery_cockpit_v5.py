"""Static contract checks for the offline browser recovery v5 surface.

These checks establish required source invariants; they are not execution,
cryptographic interoperability or security-penetration tests.
"""
from html.parser import HTMLParser
from pathlib import Path
import unittest


HTML = Path(__file__).with_name("recovery-cockpit-v5.html")


class Reader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = []

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        for key in ("src", "href", "action"):
            if tag in ("script", "iframe", "link", "img", "form"):
                if fields.get(key):
                    self.resources.append((tag, key, fields[key]))


class CockpitV5ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML.read_text(encoding="utf-8")
        parser = Reader()
        parser.feed(cls.source)
        cls.resources = parser.resources

    def test_no_external_resources(self):
        self.assertEqual(self.resources, [])

    def test_hash_domain_matches_python(self):
        self.assertIn('PALACO-OFFLINE-STAGE-v1:GENESIS', self.source)
        self.assertIn('PALACO-OFFLINE-STAGE-v1:EVENT', self.source)
        self.assertIn("String.fromCharCode(0)", self.source)

    def test_uses_browser_digest(self):
        self.assertIn('crypto.subtle.digest("SHA-256"', self.source)
        self.assertIn("SHA-256 niet beschikbaar: inspectie geweigerd", self.source)

    def test_no_trust_claim_from_hash(self):
        self.assertIn('CHAIN_VALID_UNTRUSTED', self.source)
        self.assertIn('externalVerification:"UNKNOWN"', self.source)
        self.assertIn('authorization:"DENY"', self.source)
        self.assertIn("productionReleaseEnabled:false", self.source)

    def test_rejects_replay_and_head_mismatch(self):
        for token in ("event.previous !== current", "seen.has(event.event_id)",
                      "current !== document.head"):
            self.assertIn(token, self.source)

    def test_local_file_only(self):
        self.assertIn('type="file"', self.source)
        self.assertIn('await file.text()', self.source)
        self.assertIn("8388608", self.source)
        for forbidden in ("XMLHttpRequest(", "WebSocket(", "fetch(", "innerHTML",
                          "document.write("):
            self.assertNotIn(forbidden, self.source)

    def test_no_restore_authority(self):
        self.assertNotIn("restore_to_new_file(", self.source)
        self.assertNotIn("approve(", self.source)
        self.assertIn("HOLD", self.source)

    def test_stale_async_file_selection_ignored(self):
        self.assertIn("++selectionId", self.source)
        self.assertIn("thisSelection !== selectionId", self.source)

    def test_report_does_not_export_event_data(self):
        self.assertIn('schema:"palaco-cockpit-report/v5"', self.source)
        self.assertIn("URL.createObjectURL", self.source)
        self.assertIn("URL.revokeObjectURL", self.source)


if __name__ == "__main__":
    unittest.main()
