"""PALACO v26 owner decision cockpit, offline-first candidate.

A daily JA/NEE is an authenticated *acknowledgment* of local diagnostic evidence,
NEVER permission to execute recovery or authorize release. Neither an identity
provider nor a trusted clock or independent anchor is implemented here.
"""
from datetime import date
from html import escape

from recovery_operations_cockpit_v25 import (
    CockpitError, _snapshot_check, snapshot, OwnerReviewLedger,
)

SCHEMA = "palaco-owner-decision-cockpit/v26"


class DecisionCockpitError(ValueError):
    pass


def _day(day):
    if type(day) is not str:
        raise DecisionCockpitError("INVALID_DATE")
    try:
        parsed = date.fromisoformat(day)
    except ValueError as exc:
        raise DecisionCockpitError("INVALID_DATE") from exc
    if parsed.isoformat() != day:
        raise DecisionCockpitError("INVALID_DATE")
    return parsed


class OwnerDecisionCockpit:
    """Read a fresh v24 supervisor snapshot and the existing v25 daily ledger.

    The ledger's verifier callbacks remain external; passing mocked providers
    demonstrates only the software contract, not real owner authentication.
    """

    def __init__(self, *, supervisor, ledger):
        if not callable(getattr(supervisor, "inspect", None)) or not (
                isinstance(ledger, OwnerReviewLedger)):
            raise DecisionCockpitError("INVALID_DEPENDENCIES")
        self._supervisor = supervisor
        self._ledger = ledger

    def overview(self, *, day):
        parsed = _day(day)
        current = snapshot(self._supervisor)
        _snapshot_check(current)
        previous = self._ledger.read(day=day)
        sunday = parsed.weekday() == 6
        already = previous is not None
        return {
            "schema": SCHEMA,
            "day": day,
            "snapshot": current,
            "review": previous,
            "review_available": not sunday and not already,
            "review_reason": ("SUNDAY_FREE" if sunday else
                              "ALREADY_REVIEWED" if already else "AWAITING_OWNER"),
            "authorization": "DENY",
            "release": "HOLD",
            "operations_enabled": False,
            "production_release_enabled": False,
        }

    def record(self, *, day, verdict, owner_id, evidence_ref,
               expected_snapshot_sha256, verify_owner, verify_trusted_date):
        """Record one JA/NEE only for an unchanged, fresh diagnostic snapshot.

        A second read helps reject obvious stale decisions; no cross-database
        atomicity is claimed. No recovery execution method exists here.
        """
        if type(expected_snapshot_sha256) is not str:
            raise DecisionCockpitError("INVALID_EXPECTED_SNAPSHOT")
        view = self.overview(day=day)
        if not view["review_available"]:
            raise DecisionCockpitError(view["review_reason"])
        first = view["snapshot"]
        if first["snapshot_sha256"] != expected_snapshot_sha256:
            raise DecisionCockpitError("STALE_SNAPSHOT")
        second = snapshot(self._supervisor)
        if second != first:
            raise DecisionCockpitError("SNAPSHOT_CHANGED")
        return self._ledger.record(
            second, day=day, verdict=verdict, owner_id=owner_id,
            evidence_ref=evidence_ref, verify_owner=verify_owner,
            verify_trusted_date=verify_trusted_date)


def render_owner_html(view):
    """Mobile static presentation only; no fake live JA/NEE submission."""
    if type(view) is not dict or set(view) != {
            "schema", "day", "snapshot", "review", "review_available",
            "review_reason", "authorization", "release",
            "operations_enabled", "production_release_enabled"
    } or view["schema"] != SCHEMA:
        raise DecisionCockpitError("INVALID_VIEW")
    _day(view["day"])
    _snapshot_check(view["snapshot"])
    if (type(view["review_available"]) is not bool or
            view["authorization"] != "DENY" or view["release"] != "HOLD" or
            view["operations_enabled"] is not False or
            view["production_release_enabled"] is not False):
        raise DecisionCockpitError("UNSAFE_VIEW")
    if view["review"] is not None:
        record = view["review"]
        if (type(record) is not dict or record.get("day") != view["day"] or
                record.get("snapshot_sha256") is None or
                record.get("authorization") != "DENY" or
                record.get("release") != "HOLD" or
                record.get("action_executed") is not False or
                record.get("verdict") not in ("JA", "NEE")):
            raise DecisionCockpitError("INVALID_REVIEW")
    expected_reason = (
        "SUNDAY_FREE" if _day(view["day"]).weekday() == 6 else
        "ALREADY_REVIEWED" if view["review"] is not None else
        "AWAITING_OWNER")
    if (view["review_reason"] != expected_reason or
            view["review_available"] is not (
                expected_reason == "AWAITING_OWNER")):
        raise DecisionCockpitError("INCONSISTENT_VIEW")
    s = view["snapshot"]
    labels = [
        ("Datum", view["day"]), ("Herstelstatus", s["status"]),
        ("Checkpoint", s["target_sequence"] if s["pending"] else "Geen"),
        ("Pogingen", str(s["attempts"]) + " / " + str(s["max_attempts"])),
        ("Foutcode", s["last_error"] or "Geen"),
        ("Bewijssnapshot SHA-256", s["snapshot_sha256"]),
        ("Beoordeling", view["review"]["verdict"] if view["review"] else "Nog niet vastgelegd"),
    ]
    rows = "".join(
        "<tr><th scope='row'>" + escape(str(k)) + "</th><td>" +
        escape(str(v)) + "</td></tr>" for k, v in labels)
    explanation = {
        "SUNDAY_FREE": "Zondag vrij — geen beoordeling.",
        "ALREADY_REVIEWED": "De dagelijkse beoordeling is al vastgelegd.",
        "AWAITING_OWNER": "JA of NEE kan uitsluitend via onafhankelijk geverifieerde eigenaarregistratie worden vastgelegd.",
    }[expected_reason]
    return (
        "<!doctype html><html lang='nl'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none';style-src 'unsafe-inline';base-uri 'none';form-action 'none'\">"
        "<title>PALACO · Owner Decision v26</title>"
        "<style>:root{color-scheme:dark}body{margin:auto;max-width:850px;padding:clamp(1rem,4vw,3rem);"
        "background:#081f19;color:#eee9d4;font:16px system-ui}"
        "h1{color:#e4c57a;font-size:clamp(1.6rem,4vw,2.5rem)}"
        "section{border:1px solid #6b795a;border-radius:18px;padding:1.2rem}"
        "table{width:100%;border-collapse:collapse;overflow-wrap:anywhere}"
        "th,td{padding:.8rem;text-align:left;border-bottom:1px solid #4c6655}"
        "th{width:38%}.choices{display:flex;gap:1rem;margin:1rem 0}"
        "button{flex:1;padding:1rem;border-radius:12px;border:1px solid #8a886f;"
        "background:#243a30;color:#f5db94;font-size:1.1rem;opacity:.6}"
        "small{color:#f5ca8d}</style></head><body>"
        "<header><h1>PALACO · Owner Decision</h1>"
        "<p>Dagelijks beheer · Bewijs eerst · GO-13 HOLD</p></header>"
        "<main><section><h2>Hersteloverzicht</h2><table>" + rows + "</table></section>"
        "<section><h2>Dagelijkse JA / NEE</h2><p>" + escape(explanation) + "</p>"
        "<div class='choices'><button type='button' disabled aria-label='JA, niet verbonden'>JA</button>"
        "<button type='button' disabled aria-label='NEE, niet verbonden'>NEE</button></div>"
        "<small>De knoppen zijn bewust uitgeschakeld: geen live inlog- of vertrouwensdienst."
        " JA/NEE is nooit een herstelautorisatie.</small></section></main>"
        "<footer><p>Authorization DENY · Release HOLD · Geen uitvoering</p></footer></body></html>"
    )
