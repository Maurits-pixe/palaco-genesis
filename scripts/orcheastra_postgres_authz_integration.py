#!/usr/bin/env python3
"""v0.25 ephemeral PostgreSQL auth-revocation CAS regression matrix.

The principal argument below is TEST FIXTURE data, not authentication.
The trusted service must bind it to an authenticated principal; this
script only verifies atomic storage-policy decisions. Never run against
PALACO production or a non-disposable server.
"""
import os
import subprocess
import sys

URI = os.environ.get("PALACO_TEST_PG_URI", "")
FUNC = "palaco_orcheastra_audit.publish_authorized_checkpoint"
ZERO = "decode(repeat('00',32),'hex')"
ONE = "decode(repeat('11',32),'hex')"
PLAN = "decode(repeat('aa',32),'hex')"


def query(statement: str) -> str:
    result = subprocess.run(
        ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", URI, "-c", statement],
        capture_output=True,
        text=True,
        timeout=35,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr.strip())
    return result.stdout.strip()


def expect(actual: str, wanted: str, reason: str) -> None:
    if actual != wanted:
        raise AssertionError(f"{reason}: expected {wanted!r}, got {actual!r}")


def seed(journal: str, principal: str = "service-a") -> None:
    query(
        "INSERT INTO palaco_orcheastra_audit.journal_state "
        "(journal_id,generation,plan_hash,sequence,chain_head,active_key_id) "
        f"VALUES ('{journal}',0,{PLAN},0,{ZERO},'key1');"
        "INSERT INTO palaco_orcheastra_audit.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        f"VALUES ('{journal}','key1',0,100,false);"
        "INSERT INTO palaco_orcheastra_audit.caller_policy "
        "(journal_id,principal_id,may_publish,revoked) "
        f"VALUES ('{journal}','{principal}',true,false);"
    )
    expect(query("SELECT authorization_epoch FROM "
                 "palaco_orcheastra_audit.journal_state "
                 f"WHERE journal_id='{journal}'"),
           "1", "caller policy version starts at one")


def attempt(journal: str, principal: str, auth_epoch: int) -> str:
    return query(
        f"SELECT {FUNC}('{journal}','{principal}',{auth_epoch},"
        f"0,0,{ZERO},1,1,1,{ONE},{PLAN},'key1')"
    )


def test() -> None:
    seed("authz-valid")
    expect(attempt("authz-valid", "service-a", 1), "t", "current authority permits CAS")
    expect(attempt("authz-valid", "service-a", 1), "f", "replayed CAS denied")
    expect(query("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
                 "WHERE journal_id='authz-valid'"), "1", "single ledger record")

    seed("authz-revoked")
    query("UPDATE palaco_orcheastra_audit.caller_policy SET revoked=true "
          "WHERE journal_id='authz-revoked' AND principal_id='service-a'")
    expect(attempt("authz-revoked", "service-a", 1), "f",
           "pre-revocation epoch is stale")
    expect(attempt("authz-revoked", "service-a", 2), "f",
           "revoked principal denied at current epoch")

    seed("authz-scoped")
    expect(attempt("authz-scoped", "service-b", 1), "f",
           "unknown principal cannot publish")
    expect(attempt("no-such-journal", "service-a", 1), "f",
           "unrecognized journal cannot publish")

    seed("authz-removed")
    query("UPDATE palaco_orcheastra_audit.caller_policy "
          "SET may_publish=false WHERE journal_id='authz-removed'")
    expect(attempt("authz-removed", "service-a", 2), "f",
           "operation permission revoked")
    expect(query("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
                 "WHERE journal_id IN ('authz-revoked','authz-scoped','authz-removed')"),
           "0", "denials must not create ledger records")

    seed("authz-rollback")
    result = query(
        "BEGIN;"
        f"SELECT {FUNC}('authz-rollback','service-a',1,0,0,{ZERO},1,1,1,"
        f"{ONE},{PLAN},'key1');"
        "ROLLBACK;"
    )
    expect(result, "BEGIN\nt\nROLLBACK", "CAS inside rollback")
    expect(query("SELECT generation FROM palaco_orcheastra_audit.journal_state "
                 "WHERE journal_id='authz-rollback'"), "0",
           "transaction rollback restores previous generation")
    expect(query("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
                 "WHERE journal_id='authz-rollback'"), "0",
           "transaction rollback erases uncommitted ledger row")

    print("ORCHEASTRA v0.25: authorization epoch and rollback PASS")


if __name__ == "__main__":
    if (
        not URI.startswith("postgresql://")
        or "@127.0.0.1:" not in URI
        or os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
    ):
        print("Requires disposable loopback PostgreSQL CI database", file=sys.stderr)
        sys.exit(2)
    test()
