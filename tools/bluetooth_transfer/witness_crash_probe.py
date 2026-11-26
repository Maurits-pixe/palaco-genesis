"""Crash injection: terminate child after witness commit, before SQLite commit.

Only used by the test harness. No privileged service, secure witness or
production recovery action is available in this probe.
"""
import os
from pathlib import Path
import sys

from native_checkpoint_scope import NativeCheckpoint
from sqlite_fencing_reference import SQLiteFencingReference
from witnessed_sqlite_fencing import WitnessedFencingService
from file_witness_fixture import FileWitnessFixture

NS = b"r" * 32
ROOT = "a" * 64
EXIT_AFTER_WITNESS = 73


class CrashAfterWitness(FileWitnessFixture):
    def advance(self, previous, current):
        super().advance(previous, current)
        os._exit(EXIT_AFTER_WITNESS)


def main(args):
    if len(args) != 3 or args[0] not in ("cas", "incident"):
        return 2
    action, db, witness_file = args
    sqlite = SQLiteFencingReference(Path(db), NS)
    witness = CrashAfterWitness(Path(witness_file), NS)
    service = WitnessedFencingService(sqlite, witness, NS)
    if action == "cas":
        service.compare_and_advance(
            service.read(), NativeCheckpoint(NS, 1, ROOT),
        )
    else:
        service.latch_incident()
    return 3  # should be unreachable


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
