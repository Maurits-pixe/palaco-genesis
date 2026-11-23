# Delegation Receipt Archive v0.1 — DRAFT / GO-13 HOLD

The offline verifier `tools/delegation_receipt_archive.py` accepts a
bounded list of independently Ed25519-signed archive *declarations*.
Each record hashes the previous signed archive record and embeds the
audit checkpoint count/head plus 2–16 detached witness signatures.
The first and last archive record hashes and minimum archive record
count are separately authenticated inputs. So are the audit-chain head
and event-count floor, organization rosters, key roots and revocations.

The verifier checks receipt audit/index consistency read-only, each
record's strictly increasing receipt count and prefix hash against the
full local SQLite chain, cryptographic signatures of both the independent
archive custodian and all witnesses, organizational uniqueness, role
separation and external anti-rollback pins. The latest archive
checkpoint must match the latest fully verified local receipt chain.
An old or contradictory checkpoint never overrides current history.

**Limitations:** a signed declaration does NOT prove actual off-device
retention, tamper-proof custody, independent ownership, trusted time,
legal organizational separation, or that unseen statements were not
withheld. The program does NOT sign, export, send or store archives, and
cannot maintain external pins. The same archive custodian organization
must persist across this history. All successful outcomes remain
`pending-review`; GO-13 HOLD, no release or recovery authority.

Run `python3 -m unittest discover -s tests -p 'test_delegation_receipt_archive.py' -v`.
