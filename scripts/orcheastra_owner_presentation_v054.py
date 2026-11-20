#!/usr/bin/env python3
"""ORCHEASTRA v0.54: read-only owner decision presentation gate (CI only).

No real owner has authenticated, decided or been notified. This gate
renders a safe, non-interactive proof-backed report of the v0.53 CI
fixture. It never offers an approval action, authorizes a trust change,
or opens the database for write. No hosting, external audit pin or app.
"""
import hashlib
import html
import json
import os
from pathlib import Path
import sqlite3
import sys

from orcheastra_policy_signed_checkpoint import canonical
from orcheastra_evidence_handoff_v037 import parse
from orcheastra_owner_decision_dossier_v053 import (
    CASE, VOTES, TRUST, EVIDENCE, DOSSIER, PIN, YES, NO, HEAD, DB,
    GENESIS, HEAD_DOMAIN, sha, validate_dossier, verify_decision,
)

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "orcheastra-v054"
PRESENTATION = ROOT / "owner-presentation.json"
HTML = ROOT / "owner-presentation.html"
SEAL = ROOT / "presentation-sha256.txt"
DOMAIN = "PALACO:ORCHEASTRA:OWNER_PRESENTATION_GATE:v1"
ALLOWED_RISKS = [
    "POSSIBLE_ROOT_COMPROMISE", "UNTRUSTED_REPLACEMENT",
    "LOCAL_CI_TRUST_ONLY", "NO_PRODUCTION_APPROVAL",
]


def verify_chain(database: Path, dossier_sha: str) -> tuple:
    if not database.is_file():
        raise AssertionError("audit database missing: HOLD")
    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AssertionError("SQLite audit integrity check failed")
        rows = conn.execute(
            "SELECT sequence,previous_hash,event,event_hash "
            "FROM history ORDER BY sequence"
        ).fetchall()
        triggers = {item[0] for item in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()}
        if not {"history_no_update", "history_no_delete"} <= triggers:
            raise AssertionError("audit mutation protection missing")
    finally:
        conn.close()
    if len(rows) != 2:
        raise AssertionError("exactly two immutable audit events required")
    predecessor = GENESIS
    for index, (number, previous_hash, raw, event_hash) in enumerate(rows, 1):
        if (number != index or previous_hash != predecessor
            or event_hash != sha(canonical({
                "previous": predecessor, "event": raw.hex()
            }))):
            raise AssertionError("audit history hash chain broken")
        event = parse(raw)
        if (event.get("authorization") != "NONE"
            or event.get("execution") != "HOLD"
            or event.get("dossier_sha256") != dossier_sha):
            raise AssertionError("unsafe audit event or substituted dossier")
        if index == 1 and event.get("type") != "DOSSIER_CREATED":
            raise AssertionError("missing dossier genesis")
        if index == 2 and (event.get("choice") not in ("JA", "NEE")
                           or not isinstance(event.get("decision_sha256"), str)
                           or event.get("case_sha256") !=
                           parse(DOSSIER.read_bytes())["case_sha256"]):
            raise AssertionError("invalid historical decision evidence")
        predecessor = event_hash
    return rows, predecessor


def verify_bundle(database: Path, dossier_raw: bytes, head_raw: bytes,
                  owner_pin: dict, selected: dict) -> dict:
    dossier = parse(dossier_raw)
    if canonical(dossier) != dossier_raw:
        raise AssertionError("noncanonical dossier rejected")
    validate_dossier(dossier)
    if owner_pin.get("owner_authority") != "CI_FIXTURE_ONLY":
        raise AssertionError("real owner identity must not be inferred")
    decision = verify_decision(selected, dossier, owner_pin)
    dossier_digest = sha(dossier_raw)
    rows, terminal = verify_chain(database, dossier_digest)
    head = parse(head_raw)
    if head != {
        "format": HEAD_DOMAIN, "sequence": 2, "event_hash": terminal,
        "dossier_sha256": dossier_digest,
        "authorization": "NONE", "execution": "HOLD",
    }:
        raise AssertionError("ledger head mismatch: HOLD")
    recorded = parse(rows[1][2])
    if (recorded["choice"] != decision["choice"]
        or recorded["decision_sha256"] != sha(canonical(selected))
        or recorded["case_sha256"] != decision["case_sha256"]):
        raise AssertionError("signed decision is not recorded in audit ledger")
    if dossier.get("risks") != ALLOWED_RISKS:
        raise AssertionError("risk information missing")
    return {
        "format": DOMAIN,
        "presentation_status": "EVIDENCE_VERIFIED_CI_ONLY",
        "owner_identity": "UNVERIFIED_REAL_OWNER",
        "owner_action": "NONE",
        "case_sha256": dossier["case_sha256"],
        "dossier_sha256": dossier_digest,
        "incident_evidence_sha256": dossier["evidence_sha256"],
        "review_votes_sha256": dossier["votes_sha256"],
        "review_trust_sha256": dossier["review_trust_sha256"],
        "custody_sha256": dossier["custody_sha256"],
        "audit_head_sha256": sha(head_raw),
        "audit_events": 2,
        "scope": dossier["scope"],
        "risks": ALLOWED_RISKS,
        "recorded_ci_choice": decision["choice"],
        "choice_origin": "DISPOSABLE_TEST_SIGNER",
        "review_verdict": "REVIEW_READY_HOLD",
        "root_activation": "DENIED",
        "authorization": "NONE",
        "execution": "HOLD",
    }


def render(report: dict) -> bytes:
    # Deliberately static, no form, hyperlinks, script, external assets, or JS.
    rows = [
        ("Dossier", report["dossier_sha256"]),
        ("Incident", report["case_sha256"]),
        ("Bewijshash", report["incident_evidence_sha256"]),
        ("Review quorum", report["review_votes_sha256"]),
        ("Custody", report["custody_sha256"]),
        ("Auditkop", report["audit_head_sha256"]),
        ("CI-testkeuze (geen ownerbesluit)", report["recorded_ci_choice"]),
        ("Echte eigenaar", report["owner_identity"]),
        ("Activering", report["root_activation"]),
        ("Autorisatie", report["authorization"]),
        ("Uitvoering", report["execution"]),
    ]
    cells = "".join(
        "<tr><th scope='row'>" + html.escape(label) + "</th><td>"
        + html.escape(value, quote=True) + "</td></tr>"
        for label, value in rows
    )
    risks = "".join("<li>" + html.escape(value) + "</li>"
                    for value in report["risks"])
    page = (
        "<!doctype html><html lang='nl'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'\">"
        "<title>ORCHEASTRA — Owner Decision Dossier (CI/HOLD)</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:850px;"
        "padding:2rem;margin:auto;background:#111a17;color:#eff5ec}"
        "h1{color:#d9b874}table{width:100%;border-collapse:collapse}"
        "th,td{padding:.6rem;border-bottom:1px solid #45534b;text-align:left;"
        "overflow-wrap:anywhere}th{width:35%}strong{color:#efca88}"
        "</style></head><body><main>"
        "<h1>ORCHEASTRA — Owner Decision Dossier</h1>"
        "<p><strong>CI-SIMULATIE — GEEN ECHTE EIGENAARBESLISSING</strong></p>"
        "<p>Alleen-lezen bewijsweergave. Geen knoppen, geen verzending, "
        "geen root-activering. Een test-JA is uitsluitend een testregistratie.</p>"
        "<table><tbody>" + cells + "</tbody></table><h2>Risico's</h2><ul>"
        + risks + "</ul><p>Beslissing door echte eigenaar: NIET UITGEVOERD. "
        "GO-13 HOLD; PR #348 DRAFT. Geen productiebevoegdheid.</p>"
        "</main></body></html>"
    )
    return page.encode("utf-8")


def reject(fn, label: str) -> None:
    try:
        fn()
    except (AssertionError, ValueError, KeyError, TypeError, sqlite3.Error, OSError):
        return
    raise AssertionError("unsafe owner presentation accepted: " + label)


def selected_signature() -> dict:
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT event FROM history WHERE sequence=2"
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise AssertionError("decision event missing")
    choice = parse(row[0])["choice"]
    if choice not in ("JA", "NEE"):
        raise AssertionError("invalid test choice")
    return parse((YES if choice == "JA" else NO).read_bytes())


def create() -> None:
    if ROOT.exists():
        raise AssertionError("refuse to overwrite owner presentation evidence")
    signed = selected_signature()
    dossier = DOSSIER.read_bytes()
    head = HEAD.read_bytes()
    pin = parse(PIN.read_bytes())
    report = verify_bundle(DB, dossier, head, pin, signed)
    ROOT.mkdir(parents=True, mode=0o700)
    reject(lambda: verify_bundle(
        DB, canonical({**parse(dossier), "evidence_sha256": "00"*32}),
        head, pin, signed), "changed incident digest")
    reject(lambda: verify_bundle(DB, dossier, head,
        {**pin, "owner_authority": "REAL_OWNER"}, signed),
        "CI signer impersonates production owner")
    reject(lambda: verify_bundle(DB, dossier, head, pin,
        {**signed, "signature_hex": "00"*64}),
        "invalid owner test signature")
    reject(lambda: verify_bundle(DB, dossier, head, pin,
        {**signed, "decision": {
            **signed["decision"], "root_activation": "ALLOW"}}),
        "test decision escalates to activation")
    reject(lambda: verify_bundle(DB, canonical({**parse(dossier),
        "risks": []}), head, pin, signed),
        "risk disclosure removed")
    reject(lambda: verify_bundle(DB, dossier, canonical({
        **parse(head), "event_hash": "00"*32}), pin, signed),
        "mismatched audit high-water")
    reject(lambda: verify_bundle(ROOT / "missing.sqlite3",
        dossier, head, pin, signed), "missing ledger")
    alternative = NO if signed["decision"]["choice"] == "JA" else YES
    reject(lambda: verify_bundle(DB, dossier, head, pin,
        parse(alternative.read_bytes())), "wrong signed choice not in ledger")
    presentation_raw = canonical(report)
    page_raw = render(report)
    if b"<form" in page_raw or b"<script" in page_raw or b"ACTIVATE_ROOT" in page_raw:
        raise AssertionError("presentation contains active controls")
    PRESENTATION.write_bytes(presentation_raw)
    HTML.write_bytes(page_raw)
    SEAL.write_bytes(canonical({
        "report_sha256": sha(presentation_raw),
        "html_sha256": sha(page_raw),
        "authorization": "NONE",
        "execution": "HOLD",
    }))
    print("ORCHEASTRA v0.54: safe read-only CI-only dossier, 8 adversarial cases PASS")


def verify_after_restart() -> None:
    report = verify_bundle(DB, DOSSIER.read_bytes(), HEAD.read_bytes(),
                           parse(PIN.read_bytes()), selected_signature())
    expected = canonical(report)
    if PRESENTATION.read_bytes() != expected or HTML.read_bytes() != render(report):
        raise AssertionError("presented evidence changed after restart")
    if parse(SEAL.read_bytes()) != {
        "report_sha256": sha(expected), "html_sha256": sha(HTML.read_bytes()),
        "authorization": "NONE", "execution": "HOLD"
    }:
        raise AssertionError("local presentation seal invalid")
    print("ORCHEASTRA v0.54: read-only evidence presentation intact; "
          "owner not authenticated; GO-13 HOLD")


def main() -> None:
    uri = os.environ.get("PALACO_TEST_PG_URI", "")
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not uri.startswith("postgresql://")
        or "@127.0.0.1:" not in uri):
        raise AssertionError("disposable loopback CI required")
    if sys.argv[1:] == ["--create"]:
        create()
    elif sys.argv[1:] == ["--verify"]:
        verify_after_restart()
    else:
        raise AssertionError("expected --create or --verify")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError, TypeError, KeyError, OSError, sqlite3.Error) as exc:
        print(f"ORCHEASTRA v0.54 FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
