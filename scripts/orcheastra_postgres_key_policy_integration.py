#!/usr/bin/env python3
"""ORCHEASTRA v0.28 ephemeral PostgreSQL key-policy hardening matrix.

This exercises database locking/permissions, not real HMAC signing or
production key custody. Requires disposable loopback CI PostgreSQL.
"""
import concurrent.futures
import os
import subprocess
import sys
import threading

ADMIN_URI = os.environ.get("PALACO_TEST_PG_URI", "")
PUBLISHER_URI = os.environ.get("PALACO_TEST_PUBLISHER_URI", "")
ZERO = "decode(repeat('00',32),'hex')"
ONE = "decode(repeat('11',32),'hex')"
PLAN = "decode(repeat('aa',32),'hex')"
PREFIX = "palaco_orcheastra_audit"
PRINCIPAL = "palaco_audit_ci_publisher"


def run(uri: str, command: str, *, denied: bool = False) -> str:
    result = subprocess.run(
        ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
         "-v", "statement_timeout=15000", uri, "-c",
         "SET statement_timeout='15s';" + command],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if denied:
        if result.returncode == 0 or "permission denied" not in result.stderr.lower():
            raise AssertionError(f"expected permission denial: {result.stderr.strip()}")
    elif result.returncode:
        raise AssertionError(result.stderr.strip())
    return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""


def eq(actual: str, wanted: str, reason: str) -> None:
    if actual != wanted:
        raise AssertionError(f"{reason}: expected {wanted!r}, got {actual!r}")


def seed(journal: str) -> None:
    run(
        ADMIN_URI,
        f"INSERT INTO {PREFIX}.journal_state "
        "(journal_id,generation,plan_hash,sequence,chain_head,active_key_id) "
        f"VALUES ('{journal}',0,{PLAN},0,{ZERO},'key1');"
        f"INSERT INTO {PREFIX}.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        f"VALUES ('{journal}','key1',0,100,false);"
        f"INSERT INTO {PREFIX}.caller_policy "
        "(journal_id,principal_id,may_publish,revoked) "
        f"VALUES ('{journal}','{PRINCIPAL}',true,false);"
    )


def publish(journal: str, policy_epoch: int = 1) -> str:
    return run(
        PUBLISHER_URI,
        f"SELECT {PREFIX}.publish_for_session("
        f"'{journal}',1,0,0,{ZERO},{policy_epoch},1,1,{ONE},{PLAN},'key1')",
    )


def run_tests() -> None:
    seed("key-revoke")
    eq(publish("key-revoke"), "t", "baseline authorized publication")
    # Do not reuse a committed checkpoint as though it were a new one.
    seed("key-race")
    start = threading.Barrier(2)

    def request_publish() -> str:
        start.wait(timeout=10)
        return publish("key-race")

    def request_revoke() -> str:
        start.wait(timeout=10)
        return run(ADMIN_URI, f"SELECT {PREFIX}.set_key_revocation("
                   "'key-race','key1',true)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        p = pool.submit(request_publish)
        r = pool.submit(request_revoke)
        outcome = p.result(timeout=25)
        eq(r.result(timeout=25), "t", "key revocation committed")

    if outcome not in ("t", "f"):
        raise AssertionError("invalid race result")
    eq(run(ADMIN_URI, f"SELECT revoked::text FROM {PREFIX}.key_policy "
           "WHERE journal_id='key-race'"), "true", "key remains revoked")
    eq(run(ADMIN_URI, f"SELECT policy_epoch FROM {PREFIX}.journal_state "
           "WHERE journal_id='key-race'"), "2", "key revocation advances epoch")
    eq(publish("key-race", 2), "f", "revoked key blocked after race")
    eq(run(ADMIN_URI, f"SELECT count(*) FROM {PREFIX}.anchor_history "
           "WHERE journal_id='key-race'"), "1" if outcome == "t" else "0",
       "race produces at most one committed anchor")

    seed("key-rotate")
    run(ADMIN_URI, f"INSERT INTO {PREFIX}.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        "VALUES ('key-rotate','key2',1,100,false)")
    eq(run(ADMIN_URI, f"SELECT {PREFIX}.rotate_active_key('key-rotate','key2')"),
       "t", "eligible key rotation")
    eq(run(ADMIN_URI, f"SELECT active_key_id || ':' || policy_epoch "
           f"FROM {PREFIX}.journal_state WHERE journal_id='key-rotate'"),
       "key2:3", "rotation pins new key and advances policy epoch")
    eq(publish("key-rotate", 3), "f", "old key cannot publish after rotation")
    eq(run(ADMIN_URI, f"SELECT {PREFIX}.rotate_active_key('key-rotate','key2')"),
       "f", "duplicate rotation denied")
    eq(run(ADMIN_URI, f"SELECT {PREFIX}.rotate_active_key('key-rotate','unknown')"),
       "f", "unknown key denied")

    seed("key-delete")
    # Deleting policy rows can erase revocation state. Both policy
    # collections must reject physical DELETE, including for an owner.
    for table in ("key_policy", "caller_policy"):
        result = subprocess.run(
            ["psql", "-X", "-v", "ON_ERROR_STOP=1", ADMIN_URI, "-c",
             f"DELETE FROM {PREFIX}.{table} WHERE journal_id='key-delete'"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if result.returncode == 0 or "deletion prohibited" not in result.stderr:
            raise AssertionError(f"{table} physical delete was not blocked")
    eq(run(ADMIN_URI, f"SELECT count(*) FROM {PREFIX}.key_policy "
           "WHERE journal_id='key-delete'"), "1", "key tombstone retained")
    eq(run(ADMIN_URI, f"SELECT count(*) FROM {PREFIX}.caller_policy "
           "WHERE journal_id='key-delete'"), "1", "caller tombstone retained")

    run(PUBLISHER_URI, f"SELECT {PREFIX}.set_key_revocation("
        "'key-delete','key1',false)", denied=True)
    run(PUBLISHER_URI, f"SELECT {PREFIX}.rotate_active_key("
        "'key-delete','key1')", denied=True)
    print("ORCHEASTRA v0.28: key revocation, rotation, deletion, RBAC and race PASS")


if __name__ == "__main__":
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not ADMIN_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in ADMIN_URI
        or not PUBLISHER_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in PUBLISHER_URI):
        sys.exit("refusing non-ephemeral or non-loopback PostgreSQL")
    run_tests()
