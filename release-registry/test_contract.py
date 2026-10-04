import hashlib
import json
from pathlib import Path
import unittest

class ContractTests(unittest.TestCase):
    def test_pin_and_closed_gates(self):
        root=Path(__file__).parent
        raw=(root/'contract.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),(root/'contract.sha256').read_text().split()[0])
        c=json.loads(raw)
        self.assertEqual(c['status'],'DRAFT')
        self.assertFalse(c['production_release_enabled'])
        self.assertIsNone(c['reviewer_public_key'])
        self.assertTrue(all(value is False for value in c['merge_gates'].values()))
