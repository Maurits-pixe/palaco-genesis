import unittest
from era_boundary import time_condition


class EraBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.evidence = dict(profile='ERA-REGISTRY-INTERVAL-DRAFT-0.1',
                             edtr_digest='a'*64, source_id='synthetic-test-fixture',
                             measurement_kind='OBSERVED', sync_status='SYNCHRONIZED',
                             consensus_state='CONSISTENT',
                             earliest_utc='2026-09-26T14:00:01Z',
                             latest_utc='2026-09-26T14:00:02Z')

    def evaluate(self, **kwargs):
        return time_condition(self.evidence, not_before='2026-09-26T14:00:00Z',
                              expires_at='2026-09-26T14:05:00Z', **kwargs)

    def test_verified_interval_only_satisfies_time(self):
        self.assertEqual(self.evaluate(verified=True), 'SATISFIED')
        self.assertEqual(self.evaluate(), 'UNKNOWN')
        self.assertEqual(self.evaluate(verified=1), 'UNKNOWN')

    def test_uncertainty_overlaps_expiry(self):
        self.evidence['latest_utc'] = '2026-09-26T14:05:00Z'
        self.assertEqual(self.evaluate(verified=True), 'UNKNOWN')

    def test_uncertainty_overlaps_start(self):
        self.evidence['earliest_utc'] = '2026-09-26T13:59:59Z'
        self.assertEqual(self.evaluate(verified=True), 'UNKNOWN')

    def test_expiration_is_not_revocation(self):
        self.evidence.update(earliest_utc='2026-09-26T14:05:00Z', latest_utc='2026-09-26T14:06:00Z')
        self.assertEqual(self.evaluate(verified=True), 'EXPIRED')

    def test_missing_conflicting_and_synthetic_time(self):
        for key, values in {'consensus_state':['CONFLICT','DEGRADED','QUARANTINED','UNKNOWN'],
                            'measurement_kind':['SYNTHETIC','DERIVED','UNKNOWN'],
                            'sync_status':['STALE','SOURCE_LOST','UNSYNCED'],
                            'edtr_digest':['',None], 'source_id':['',None],
                            'earliest_utc':[None,'invented']}.items():
            original = self.evidence[key]
            for value in values:
                self.evidence[key] = value
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.evaluate(verified=True), 'UNKNOWN')
            self.evidence[key] = original

    def test_unknown_schema_fields_and_reversed_interval(self):
        self.evidence['extra'] = True
        self.assertEqual(self.evaluate(verified=True), 'UNKNOWN')
        del self.evidence['extra']
        self.evidence['earliest_utc'] = '2026-09-26T14:01:00Z'
        self.assertEqual(self.evaluate(verified=True), 'UNKNOWN')
