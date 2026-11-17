"""Static safety invariants for the standalone offline recovery cockpit.

These tests do not replace browser execution tests or security review.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

HTML = Path(__file__).with_name("recovery-cockpit-v4.html")


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external_resources = []
        self.inline_handlers = []
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self.forms += 1
        if tag in {"script", "iframe", "link", "img", "audio", "video"}:
            if attributes.get("src") or attributes.get("href"):
                self.external_resources.append((tag, attributes))
        for key in attributes:
            if key.lower().startswith("on"):
                self.inline_handlers.append((tag, key))


class RecoveryCockpitContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = HTML.read_text(encoding="utf-8")
        cls.parser = SurfaceParser()
        cls.parser.feed(cls.html)

    def test_no_external_assets(self):
        self.assertEqual(self.parser.external_resources, [])

    def test_no_html_event_handlers(self):
        self.assertEqual(self.parser.inline_handlers, [])

    def test_no_submission_form(self):
        self.assertEqual(self.parser.forms, 0)

    def test_no_automatic_network_io(self):
        self.assertNotRegex(self.html, r"\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(")

    def test_explicit_hold_and_deny(self):
        for phrase in ("GO-13", "HOLD", "authorization:\"DENY\"",
                       "productionReleaseEnabled:false"):
            self.assertIn(phrase, self.html)

    def test_local_import_only(self):
        self.assertIn('type="file"', self.html)
        self.assertIn("file.text()", self.html)
        self.assertIn("8388608", self.html)

    def test_safe_rendering(self):
        self.assertIn("textContent", self.html)
        self.assertNotIn("innerHTML", self.html)
        self.assertNotIn("document.write", self.html)

    def test_export_is_local(self):
        self.assertIn("new Blob(", self.html)
        self.assertIn("URL.createObjectURL(", self.html)
        self.assertIn("URL.revokeObjectURL(", self.html)


if __name__ == "__main__":
    unittest.main()
