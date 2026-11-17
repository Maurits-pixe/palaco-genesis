#!/usr/bin/env python3
"""Ephemeral PostgreSQL v0.26 session-bound publication regression tests.

This tests database-role authentication only, not network authentication,
HMAC signing, or a trusted production authority. Never use production data.
"""
import os
import subprocess
import sys

ADMIN_URI = os.environ.get("PALACO_TEST_PG_URI", "")
PUBLISHER_URI = os.environ.get("PALACO_TEST_PUBLISHER_URI", "")
ZERO = "decode(repeat('00',32),'hex')"
ONE = "decode(repeat('11',32),'hex')"
PLAN = "decode(repeat('aa',32),'hex')"
FACADE = "palaco_orcheastra_audit.publish_for_session"
RAW = "palaco_orcheastra_audit.publish_checkpoint"
AUTHZ = "palaco_orcheastra_audit.publish_authorized_checkpoint"
PRINCIPAL = "palaco_audit_ci_publisher"


def run(uri: str, query: str, *, success: bool = True) -> str:
    process = subprocess.run(
        ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", uri, "-c", query],
        capture_output=True,
        text=True,
        timeout=35,
        check=False,
    )
    if success:
        if process.returncode:
            raise AssertionError(process.stderr.strip())
    elif process.returncode == 0 or "permission denied" not in process.stderr.lower():
        raise AssertionError(f"expected permission denied, got {process.stderr.strip()!r}")
    return process.stdout.strip()


def equal(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def seed(journal: str) -> None:
    run(
        ADMIN_URI,
        "INSERT INTO palaco_orcheastra_audit.journal_state "
        "(journal_id,generation,plan_hash,sequence,chain_head,active_key_id) "
        f"VALUES ('{journal}',0,{PLAN},0,{ZERO},'key1');"
        "INSERT INTO palaco_orcheastra_audit.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        f"VALUES ('{journal}','key1',0,100,false);"
        "INSERT INTO palaco_orcheastra_audit.caller_policy "
        "(journal_id,principal_id,may_publish,revoked) "
        f"VALUES ('{journal}','{PRINCIPAL}',true,false);",
    )


def attempt(journal: str, epoch: int = 1, uri: str = PUBLISHER_URI) -> str:
    return run(
        uri,
        f"SELECT {FACADE}('{journal}',{epoch},0,0,{ZERO},1,1,1,"
        f"{ONE},{PLAN},'key1')",
    )


def main() -> None:
    if (
        not ADMIN_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in ADMIN_URI
        or not PUBLISHER_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in PUBLISHER_URI
        or os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
    ):
        raise AssertionError("requires isolated loopback PostgreSQL CI")

    equal(
        run(PUBLISHER_URI, "SELECT session_user"),
        PRINCIPAL,
        "authenticated PostgreSQL session principal",
    )
    # The publisher cannot bypass the session-bound function with a forged
    # principal_id or invoke unguarded publication directly.
    run(
        PUBLISHER_URI,
        f"SELECT {AUTHZ}('session-valid','fake',1,0,0,{ZERO},1,1,1,"
        f"{ONE},{PLAN},'key1')",
        success=False,
    )
    run(
        PUBLISHER_URI,
        f"SELECT {RAW}('session-valid',0,0,{ZERO},1,1,1,{ONE},{PLAN},'key1')",
        success=False,
    )

    seed("session-valid")
    equal(attempt("session-valid"), "t", "authenticated role can publish once")
    equal(attempt("session-valid"), "f", "replayed session publish denied")
    equal(
        run(ADMIN_URI, "SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id='session-valid'"),
        "1",
        "session-bound publication creates one audit record",
    )
    seed("session-revoked")
    run(ADMIN_URI, "UPDATE palaco_orcheastra_audit.caller_policy SET revoked=true "
        "WHERE journal_id='session-revoked'")
    equal(attempt("session-revoked"), "f", "stale auth epoch denied")
    equal(attempt("session-revoked", 2), "f", "revoked authenticated role denied")

    seed("session-wrong-scope")
    run(
        ADMIN_URI,
        "DELETE FROM palaco_orcheastra_audit.caller_policy "
        "WHERE journal_id='session-wrong-scope'",
    )
    equal(attempt("session-wrong-scope", 2), "f",
          "authenticated role without journal permission denied")
    equal(attempt("no-session-journal"), "f", "unknown journal denied")
    equal(
        run(ADMIN_URI, "SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id IN ('session-revoked','session-wrong-scope')"),
        "0", "denied role requests cannot append history",
    )
    print("ORCHEASTRA v0.26 session principal: scoped publish and revocation PASS")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, subprocess.TimeoutExpired) as exc:
        print(f"ORCHEASTRA v0.26 FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
