#!/usr/bin/env python3
"""ORCHEASTRA v0.29 policy evidence test on disposable local PostgreSQL only.

Tests transactional event capture, revocation history, rollback, immutable
rows and access isolation. Does not prove external tamper resistance.
"""
import os
import subprocess
import sys

ADMIN_URI = os.environ.get("PALACO_TEST_PG_URI", "")
PUBLISHER_URI = os.environ.get("PALACO_TEST_PUBLISHER_URI", "")
PREFIX = "palaco_orcheastra_audit"
ZERO = "decode(repeat('00',32),'hex')"
PLAN = "decode(repeat('aa',32),'hex')"
PRINCIPAL = "palaco_audit_ci_publisher"


def sql(uri: str, statement: str, *, reject: str = "") -> str:
    process = subprocess.run(
        ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", uri, "-c", statement],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if reject:
        if process.returncode == 0 or reject not in process.stderr.lower():
            raise AssertionError(
                f"expected rejection {reject!r}: {process.stderr.strip()!r}"
            )
    elif process.returncode:
        raise AssertionError(process.stderr.strip())
    return process.stdout.strip()


def eq(actual: str, expected: str, reason: str) -> None:
    if actual != expected:
        raise AssertionError(f"{reason}: expected {expected!r}, got {actual!r}")


def seed(journal: str) -> None:
    sql(
        ADMIN_URI,
        f"INSERT INTO {PREFIX}.journal_state "
        "(journal_id,generation,plan_hash,sequence,chain_head,active_key_id) "
        f"VALUES ('{journal}',0,{PLAN},0,{ZERO},'key1');"
        f"INSERT INTO {PREFIX}.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        f"VALUES ('{journal}','key1',0,100,false);"
        f"INSERT INTO {PREFIX}.caller_policy "
        "(journal_id,principal_id,may_publish,revoked) "
        f"VALUES ('{journal}','{PRINCIPAL}',true,false);",
    )


def check() -> None:
    seed("evidence-change")
    eq(
        sql(ADMIN_URI, f"SELECT category || ':' || epoch || ':' || old_epoch "
            f"FROM {PREFIX}.policy_change_history "
            "WHERE journal_id='evidence-change' ORDER BY category"),
        "caller:1:0\nkey:1:0",
        "initial authorization and key-policy events",
    )
    eq(
        sql(ADMIN_URI, f"SELECT {PREFIX}.set_key_revocation("
            "'evidence-change','key1',true)"),
        "t", "key revocation",
    )
    eq(
        sql(ADMIN_URI, f"SELECT {PREFIX}.set_caller_publication("
            f"'evidence-change','{PRINCIPAL}',false,true)"),
        "t", "caller revocation",
    )
    eq(
        sql(ADMIN_URI, f"SELECT category || ':' || epoch "
            f"FROM {PREFIX}.policy_change_history "
            "WHERE journal_id='evidence-change' ORDER BY category,epoch"),
        "caller:1\ncaller:2\nkey:1\nkey:2",
        "policy change history is complete and strictly increasing",
    )

    seed("evidence-rotation")
    sql(ADMIN_URI, f"INSERT INTO {PREFIX}.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        "VALUES ('evidence-rotation','key2',1,100,false)")
    eq(sql(ADMIN_URI, f"SELECT {PREFIX}.rotate_active_key("
           "'evidence-rotation','key2')"), "t", "key rotation")
    eq(
        sql(ADMIN_URI,
            f"SELECT old_epoch || ':' || epoch || ':' || previous_key_id "
            f"|| ':' || current_key_id FROM {PREFIX}.policy_change_history "
            "WHERE journal_id='evidence-rotation' AND category='key' "
            "ORDER BY epoch DESC LIMIT 1"),
        "2:3:key1:key2",
        "recorded key rotation with epoch transition",
    )

    # A direct key swap without epoch advancement is forbidden.
    sql(ADMIN_URI,
        f"UPDATE {PREFIX}.journal_state SET active_key_id='key1' "
        "WHERE journal_id='evidence-rotation'",
        reject="missing policy epoch")
    eq(
        sql(ADMIN_URI, f"SELECT active_key_id FROM {PREFIX}.journal_state "
            "WHERE journal_id='evidence-rotation'"),
        "key2", "rejected raw key swap left state unchanged",
    )
    sql(ADMIN_URI,
        f"UPDATE {PREFIX}.journal_state SET policy_epoch=0 "
        "WHERE journal_id='evidence-rotation'",
        reject="policy epoch rollback")

    seed("evidence-rollback")
    result = sql(ADMIN_URI,
        "BEGIN;"
        f"SELECT {PREFIX}.set_key_revocation("
        "'evidence-rollback','key1',true);"
        "ROLLBACK;")
    eq(result, "BEGIN\nt\nROLLBACK", "revocation transaction rolled back")
    eq(
        sql(ADMIN_URI, f"SELECT count(*) FROM {PREFIX}.policy_change_history "
            "WHERE journal_id='evidence-rollback' AND category='key'"),
        "1", "rollback did not append revocation event",
    )
    eq(
        sql(ADMIN_URI, f"SELECT revoked::text FROM {PREFIX}.key_policy "
            "WHERE journal_id='evidence-rollback'"),
        "false", "rollback preserved key state",
    )

    for operation in (
        "UPDATE policy_change_history SET epoch=99 WHERE journal_id='evidence-change'",
        "DELETE FROM policy_change_history WHERE journal_id='evidence-change'",
        "TRUNCATE policy_change_history",
    ):
        sql(ADMIN_URI, f"{operation.replace('policy_change_history', PREFIX+'.policy_change_history')}",
            reject="policy history mutation prohibited")

    sql(PUBLISHER_URI,
        f"SELECT * FROM {PREFIX}.policy_change_history",
        reject="permission denied")
    sql(PUBLISHER_URI,
        f"DELETE FROM {PREFIX}.policy_change_history WHERE journal_id='evidence-change'",
        reject="permission denied")
    eq(
        sql(ADMIN_URI, f"SELECT count(*) FROM {PREFIX}.policy_change_history "
            "WHERE journal_id='evidence-change'"),
        "4", "failed tampering did not erase events",
    )
    print("ORCHEASTRA v0.29: evidence, rotation, rollback and access PASS")


if __name__ == "__main__":
    if (os.environ.get("PALACO_TEST_EPHEMERAL") != "YES"
        or not ADMIN_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in ADMIN_URI
        or not PUBLISHER_URI.startswith("postgresql://")
        or "@127.0.0.1:" not in PUBLISHER_URI):
        sys.exit("refusing non-ephemeral or non-loopback PostgreSQL")
    check()
