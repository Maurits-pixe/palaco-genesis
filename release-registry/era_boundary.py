"""Draft ERA-008 interval check; never authorization or an EDTR signer.

This bounded seconds-only adapter uses independently verified interval inputs.
It does not parse the full ERA-002 record or invent accuracy from decimal digits.
"""
from registry import HEX, Rejected, utc


def time_condition(evidence, *, not_before, expires_at, verified=False):
    fields = {'profile', 'edtr_digest', 'source_id', 'measurement_kind',
              'sync_status', 'consensus_state', 'earliest_utc', 'latest_utc'}
    if (type(evidence) is not dict or set(evidence) != fields
            or evidence['profile'] != 'ERA-REGISTRY-INTERVAL-DRAFT-0.1'
            or verified is not True):
        return 'UNKNOWN'
    if (not isinstance(evidence['edtr_digest'], str)
            or not HEX.fullmatch(evidence['edtr_digest'])
            or not isinstance(evidence['source_id'], str)
            or not evidence['source_id'].strip()
            or evidence['measurement_kind'] != 'OBSERVED'
            or evidence['sync_status'] != 'SYNCHRONIZED'
            or evidence['consensus_state'] != 'CONSISTENT'):
        return 'UNKNOWN'
    try:
        lower, upper = utc(evidence['earliest_utc']), utc(evidence['latest_utc'])
        start, end = utc(not_before), utc(expires_at)
    except (Rejected, TypeError, ValueError):
        return 'UNKNOWN'
    if lower > upper or start >= end:
        return 'UNKNOWN'
    if lower >= end:
        return 'EXPIRED'
    if upper < start:
        return 'NOT_YET_VALID'
    if lower < start or upper >= end:
        return 'UNKNOWN'
    return 'SATISFIED'
