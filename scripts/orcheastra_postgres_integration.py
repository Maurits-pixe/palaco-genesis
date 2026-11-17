#!/usr/bin/env python3
"""Isolated PostgreSQL integration tests for ORCHEASTRA's draft SQL contract.

This harness is only intended for an ephemeral disposable database.
It never reads credentials from source files or contacts a default database.
Required environment: PALACO_TEST_PG_URI with a nonproduction connection URI.
The GitHub Actions job provisions its own local PostgreSQL container.
"""
import concurrent.futures
import os
import subprocess
import sys

URI = os.environ.get("PALACO_TEST_PG_URI", "")
ZERO = "decode(repeat('00',32),'hex')"
ONE = "decode(repeat('11',32),'hex')"
TWO = "decode(repeat('22',32),'hex')"
PLAN = "decode(repeat('aa',32),'hex')"
FUNC = "palaco_orcheastra_audit.publish_checkpoint"


def sql(statement: str) -> str:
    result = subprocess.run(
        ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", URI, "-c", statement],
        capture_output=True,
        text=True,
        check=False,
        timeout=35,
    )
    if result.returncode:
        raise RuntimeError(f"psql failed: {result.stderr.strip()}")
    return result.stdout.strip()


def assert_equal(actual: str, expected: str, why: str) -> None:
    if actual != expected:
        raise AssertionError(f"{why}: expected {expected!r}, found {actual!r}")


def seed(journal: str) -> int:
    sql(
        "INSERT INTO palaco_orcheastra_audit.journal_state "
        "(journal_id,generation,plan_hash,sequence,chain_head,active_key_id) "
        f"VALUES ('{journal}',0,{PLAN},0,{ZERO},'key1');"
        "INSERT INTO palaco_orcheastra_audit.key_policy "
        "(journal_id,key_id,first_generation,last_generation,revoked) "
        f"VALUES ('{journal}','key1',0,100,false);"
    )
    epoch = sql(
        "SELECT policy_epoch FROM palaco_orcheastra_audit.journal_state "
        f"WHERE journal_id='{journal}'"
    )
    assert_equal(epoch, "1", "policy trigger increments epoch")
    return 1


def publish(journal: str, epoch: int, next_head: str = ONE) -> str:
    return sql(
        f"SELECT {FUNC}('{journal}',0,0,{ZERO},{epoch},1,1,"
        f"{next_head},{PLAN},'key1')"
    )


def main() -> int:
    if not URI or not URI.startswith("postgresql://") or "@127.0.0.1:" not in URI:
        print("PALACO_TEST_PG_URI must identify a loopback PostgreSQL instance", file=sys.stderr)
        return 2
    if os.environ.get("PALACO_TEST_EPHEMERAL") != "YES":
        print("Refusing to run without explicit ephemeral-database guard", file=sys.stderr)
        return 2

    # Run only against the disposable container provisioned by the CI service.
    seed("test-success")
    assert_equal(publish("test-success", 1), "t", "initial CAS accepted")
    assert_equal(publish("test-success", 1), "f", "duplicate CAS denied")
    assert_equal(
        sql("SELECT generation || ':' || sequence FROM "
            "palaco_orcheastra_audit.journal_state "
            "WHERE journal_id='test-success'"),
        "1:1", "persisted generation and sequence"
    )
    assert_equal(
        sql("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id='test-success'"),
        "1", "unique ledger row"
    )

    seed("test-revoked")
    sql("UPDATE palaco_orcheastra_audit.key_policy SET revoked=true "
        "WHERE journal_id='test-revoked' AND key_id='key1'")
    assert_equal(publish("test-revoked", 1), "f", "stale policy epoch denied")
    assert_equal(publish("test-revoked", 2), "f", "revoked key denied")
    assert_equal(
        sql("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id='test-revoked'"),
        "0", "revoked key cannot write ledger"
    )

    seed("test-rollback")
    result = sql(
        "BEGIN;"
        f"SELECT {FUNC}('test-rollback',0,0,{ZERO},1,1,1,{ONE},{PLAN},'key1');"
        "ROLLBACK;"
    )
    assert_equal(result, "t", "CAS inside rollback transaction")
    assert_equal(
        sql("SELECT generation FROM palaco_orcheastra_audit.journal_state "
            "WHERE journal_id='test-rollback'"),
        "0", "rollback preserves original generation"
    )
    assert_equal(
        sql("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id='test-rollback'"),
        "0", "rollback does not leak history"
    )

    seed("test-concurrent")
    # Both callers compete to publish the same expected generation.
    # Exactly one must commit; the second sees the updated version under
    # PostgreSQL row-level locking and must return false.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(publish, "test-concurrent", 1, ONE),
            pool.submit(publish, "test-concurrent", 1, TWO),
        ]
        outcomes = sorted(f.result() for f in futures)
    assert_equal(",".join(outcomes), "f,t", "only one racing writer may commit")
    assert_equal(
        sql("SELECT generation FROM palaco_orcheastra_audit.journal_state "
            "WHERE journal_id='test-concurrent'"),
        "1", "racing writers advance only one generation"
    )
    assert_equal(
        sql("SELECT count(*) FROM palaco_orcheastra_audit.anchor_history "
            "WHERE journal_id='test-concurrent'"),
        "1", "racing writers produce one history record"
    )

    print("ORCHEASTRA PostgreSQL v0.21: CAS, duplicate, revoke, rollback, concurrency PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
