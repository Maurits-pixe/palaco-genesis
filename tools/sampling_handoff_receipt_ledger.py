#!/usr/bin/env python3
"""Local atomic registry of signed sampling-succession handoff receipts.

The only accepted disposition is received-for-independent-review.
This SQLite store and local hash chain are NOT immutable or remote.
A previously authenticated head/count pin is required for every append
and read-only inspection. No authority or receipt issuance occurs.
"""
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

_spec=importlib.util.spec_from_file_location(
    "palaco_handoff_receipt_ledger_verifier",
    Path(__file__).with_name("sampling_succession_evidence_handoff.py"))
handoff=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handoff)

DOMAIN=b"PALACO-SAMPLING-HANDOFF-RECEIPT-LEDGER-V1\x00"
RECEIPT_DOMAIN=b"PALACO-SAMPLING-HANDOFF-RECEIPT-EVIDENCE-V1\x00"
GENESIS="0"*64
MAX_RECORDS=10000
TRUST_KEYS={
    "source_db","witness_roots","witness_organizations","revoked_witnesses",
    "required_organizations","trusted_genesis","trusted_head",
    "minimum_revision","trusted_ledger_head","minimum_ledger_batches",
    "expected_recipient","expected_package_hash","expected_nonce",
    "used_nonces","recipient_roots","allowed_recipients","revoked_recipients"
}


def _out(**values):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "state":"quarantined",**values}


def _digest(number,recipient,recipient_key,package_hash,nonce,
            receipt_hash,previous):
    raw=json.dumps([number,recipient,recipient_key,package_hash,nonce,
                    receipt_hash,previous],separators=(",",":"),
                   ensure_ascii=False,allow_nan=False).encode("utf-8")
    return hashlib.sha256(DOMAIN+raw).hexdigest()


def _path(db):
    if not isinstance(db,(str,Path)) or str(db)==":memory:":
        raise ValueError("persistent-handoff-receipt-ledger-required")
    path=Path(db)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("invalid-handoff-receipt-ledger-target")
    return path


def _schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS sampling_handoff_receipts(
        sequence INTEGER PRIMARY KEY CHECK(sequence>0),
        recipient_id TEXT NOT NULL,
        recipient_key_id TEXT NOT NULL,
        package_sha256 TEXT NOT NULL,
        nonce_hex TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        UNIQUE(recipient_key_id,package_sha256))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sampling_handoff_nonces(
        nonce_hex TEXT PRIMARY KEY,
        receipt_sequence INTEGER NOT NULL UNIQUE,
        FOREIGN KEY(receipt_sequence) REFERENCES sampling_handoff_receipts(sequence))""")


def _schema_valid(conn):
    """Reject schema drift, including removed uniqueness or FK constraints."""
    expected={
        "sampling_handoff_receipts": """CREATE TABLE sampling_handoff_receipts(
        sequence INTEGER PRIMARY KEY CHECK(sequence>0),
        recipient_id TEXT NOT NULL,
        recipient_key_id TEXT NOT NULL,
        package_sha256 TEXT NOT NULL,
        nonce_hex TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        UNIQUE(recipient_key_id,package_sha256))""",
        "sampling_handoff_nonces": """CREATE TABLE sampling_handoff_nonces(
        nonce_hex TEXT PRIMARY KEY,
        receipt_sequence INTEGER NOT NULL UNIQUE,
        FOREIGN KEY(receipt_sequence) REFERENCES sampling_handoff_receipts(sequence))"""
    }
    actual=dict(conn.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='table' "
        "AND name IN (?,?)",tuple(expected)).fetchall())
    return (set(actual)==set(expected)
            and all(isinstance(actual[name],str)
                    and "".join(actual[name].split())=="".join(sql.split())
                    for name,sql in expected.items()))


def _storage_integrity_ok(conn):
    """Check SQLite structure and foreign-key consistency, without writes."""
    return (conn.execute("PRAGMA quick_check(1)").fetchone()==("ok",)
            and conn.execute("PRAGMA foreign_key_check").fetchone() is None)


def _scan(conn):
    if not _schema_valid(conn) or not _storage_integrity_ok(conn):return None
    rows=conn.execute("""SELECT sequence,recipient_id,recipient_key_id,
         package_sha256,nonce_hex,receipt_sha256,previous_hash,event_hash
         FROM sampling_handoff_receipts ORDER BY sequence LIMIT ?""",
         (MAX_RECORDS+1,)).fetchall()
    if len(rows)>MAX_RECORDS:return None
    # Bound both ledger tables: a hostile nonce index must not force an
    # unbounded allocation even if the receipt chain is small.
    pins=conn.execute("""SELECT nonce_hex,receipt_sequence
         FROM sampling_handoff_nonces LIMIT ?""",
         (MAX_RECORDS+1,)).fetchall()
    if len(pins)>MAX_RECORDS:return None
    preceding=GENESIS
    expected=set()
    recipients=set()
    for number,row in enumerate(rows,1):
        seq,recipient,key,package,nonce,receipt_hash,prior,digest=row
        if (type(seq) is not int or seq!=number
            or not isinstance(recipient,str) or not handoff.IDENT.fullmatch(recipient)
            or any(not isinstance(x,str) or not handoff.HEX.fullmatch(x)
                   for x in (key,package,nonce,receipt_hash,prior,digest))
            or prior!=preceding or
            digest!=_digest(seq,recipient,key,package,nonce,receipt_hash,prior)):
            return None
        expected.add((nonce,seq))
        recipients.add((key,package))
        preceding=digest
    if len(expected)!=len(rows) or len(recipients)!=len(rows) or set(pins)!=expected:
        return None
    return {"receipts":len(rows),"head_hash":preceding,
            "used_nonces":{item[0] for item in expected}}


def register(db,package,receipt,trust,expected_previous_head,
             minimum_existing_receipts):
    def deny(reason):return _out(recorded=False,reason=reason)
    if (not isinstance(expected_previous_head,str)
        or not handoff.HEX.fullmatch(expected_previous_head)
        or type(minimum_existing_receipts) is not int
        or not 0<=minimum_existing_receipts<=MAX_RECORDS):
        return deny("missing-independent-handoff-ledger-pin")
    if not isinstance(trust,dict) or set(trust)!=TRUST_KEYS:
        return deny("invalid-handoff-ledger-verification-policy")
    try: path=_path(db)
    except ValueError as exc:return deny(str(exc))
    try:
        with sqlite3.connect(path,timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _schema(conn)
            state=_scan(conn)
            if state is None:
                return deny("handoff-receipt-ledger-integrity-failed")
            if state["receipts"]<minimum_existing_receipts:
                return deny("handoff-receipt-ledger-rollback")
            if state["head_hash"]!=expected_previous_head:
                return deny("handoff-receipt-ledger-head-mismatch")
            if state["receipts"]>=MAX_RECORDS:
                return deny("handoff-receipt-ledger-full")
            nonce=trust["expected_nonce"]
            if not isinstance(nonce,str) or not handoff.HEX.fullmatch(nonce):
                return deny("invalid-handoff-nonce")
            if nonce in state["used_nonces"]:
                return deny("handoff-receipt-nonce-replayed")
            if not isinstance(trust["used_nonces"],(set,frozenset)):
                return deny("missing-independent-handoff-nonce-policy")
            checked=handoff.verify_receipt(
                db=trust["source_db"],
                package=package,receipt=receipt,
                **{key:value for key,value in trust.items() if key!="source_db"})
            if not checked["receipt_valid"]:
                return deny(checked["reason"])
            key=checked["recipient_key_id"]
            digest=checked["package_sha256"]
            recipient=trust["expected_recipient"]
            nonce=checked["receipt_nonce_hex"]
            evidence=hashlib.sha256(
                RECEIPT_DOMAIN+handoff.canonical(receipt)).hexdigest()
            number=state["receipts"]+1
            event=_digest(number,recipient,key,digest,nonce,evidence,state["head_hash"])
            try:
                conn.execute("INSERT INTO sampling_handoff_receipts VALUES(?,?,?,?,?,?,?,?)",
                             (number,recipient,key,digest,nonce,evidence,state["head_hash"],event))
                conn.execute("INSERT INTO sampling_handoff_nonces VALUES(?,?)",
                             (nonce,number))
            except sqlite3.IntegrityError:
                # Returning normally from a sqlite3 connection context
                # commits any earlier successful statement. The receipt
                # insert MUST be undone if the nonce insert fails.
                conn.rollback()
                return deny("duplicate-handoff-package-or-nonce")
            # Recheck the post-write state before committing: malicious
            # SQLite triggers must never result in a successful receipt claim.
            written=_scan(conn)
            if (written is None or written["receipts"]!=number
                or written["head_hash"]!=event
                or nonce not in written["used_nonces"]):
                conn.rollback()
                return deny("handoff-receipt-ledger-postwrite-integrity-failed")
    except (sqlite3.Error,TypeError,ValueError,OverflowError,OSError):
        return deny("handoff-receipt-ledger-transaction-failed")
    return _out(recorded=True,state="pending-review",
                reason="locally-indexed-handoff-receipt-no-storage-authority",
                receipts=number,head_hash=event,
                receipt_sha256=evidence)


def inspect(db,expected_head,minimum_receipts):
    def deny(reason):return _out(ledger_valid=False,reason=reason)
    if (not isinstance(expected_head,str) or not handoff.HEX.fullmatch(expected_head)
        or type(minimum_receipts) is not int
        or not 1<=minimum_receipts<=MAX_RECORDS):
        return deny("missing-independent-handoff-ledger-pin")
    try:path=_path(db)
    except ValueError as exc:return deny(str(exc))
    if not path.is_file():return deny("missing-handoff-receipt-ledger")
    try:
        conn=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            conn.execute("BEGIN")
            state=_scan(conn)
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error,ValueError,TypeError,OSError):
        return deny("unreadable-handoff-receipt-ledger")
    if state is None:return deny("handoff-receipt-ledger-integrity-failed")
    if state["receipts"]<minimum_receipts:return deny("handoff-receipt-ledger-rollback")
    if state["head_hash"]!=expected_head:return deny("handoff-receipt-ledger-head-mismatch")
    return _out(ledger_valid=True,state="pending-review",
                reason="locally-verified-handoff-receipts-against-external-pin",
                receipts=state["receipts"],head_hash=state["head_hash"])


def inspect_entry(db,expected_head,minimum_receipts,sequence):
    """Read-only inspection of one locally indexed receipt against a pinned chain.

    Returned metadata is a ledger claim, not proof of physical delivery.
    """
    def deny(reason):return _out(entry_valid=False,reason=reason)
    if (not isinstance(expected_head,str) or not handoff.HEX.fullmatch(expected_head)
        or type(minimum_receipts) is not int
        or not 1<=minimum_receipts<=MAX_RECORDS
        or type(sequence) is not int or not 1<=sequence<=MAX_RECORDS):
        return deny("invalid-independent-handoff-entry-policy")
    try:path=_path(db)
    except ValueError as exc:return deny(str(exc))
    if not path.is_file():return deny("missing-handoff-receipt-ledger")
    try:
        conn=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            conn.execute("BEGIN")
            state=_scan(conn)
            row=conn.execute("""SELECT recipient_id,recipient_key_id,
                package_sha256,nonce_hex,receipt_sha256,previous_hash,event_hash
                FROM sampling_handoff_receipts WHERE sequence=?""",
                (sequence,)).fetchone() if state is not None else None
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error,ValueError,TypeError,OSError):
        return deny("unreadable-handoff-receipt-ledger")
    if state is None:return deny("handoff-receipt-ledger-integrity-failed")
    if state["receipts"]<minimum_receipts:
        return deny("handoff-receipt-ledger-rollback")
    if state["head_hash"]!=expected_head:
        return deny("handoff-receipt-ledger-head-mismatch")
    if row is None:return deny("handoff-receipt-entry-not-found")
    recipient,key,package,nonce,receipt_hash,previous,event=row
    return _out(entry_valid=True,state="pending-review",
                reason="locally-verified-handoff-entry-not-delivery-proof",
                sequence=sequence,receipts=state["receipts"],
                head_hash=state["head_hash"],recipient_id=recipient,
                recipient_key_id=key,package_sha256=package,
                receipt_nonce_hex=nonce,receipt_sha256=receipt_hash,
                previous_hash=previous,event_hash=event)


def verify_entry_evidence(db,package,receipt,trust,expected_head,
                          minimum_receipts,sequence):
    """Reverify signed evidence and bind it to a pinned local ledger entry.

    This read-only check does not establish physical delivery or custody.
    The supplied independent nonce policy must not classify this receipt's
    already-consumed nonce as a new replay attempt.
    """
    def deny(reason):return _out(evidence_valid=False,reason=reason)
    if not isinstance(trust,dict) or set(trust)!=TRUST_KEYS:
        return deny("invalid-handoff-ledger-verification-policy")
    entry=inspect_entry(db,expected_head,minimum_receipts,sequence)
    if not entry["entry_valid"]:
        return deny(entry["reason"])
    try:
        checked=handoff.verify_receipt(
            db=trust["source_db"],package=package,receipt=receipt,
            **{key:value for key,value in trust.items() if key!="source_db"})
        if not checked["receipt_valid"]:
            return deny(checked["reason"])
        evidence=hashlib.sha256(
            RECEIPT_DOMAIN+handoff.canonical(receipt)).hexdigest()
    except (TypeError,ValueError,OverflowError,KeyError,OSError,sqlite3.Error):
        return deny("invalid-handoff-entry-evidence")
    if (checked["recipient_key_id"]!=entry["recipient_key_id"]
        or checked["package_sha256"]!=entry["package_sha256"]
        or checked["receipt_nonce_hex"]!=entry["receipt_nonce_hex"]
        or trust["expected_recipient"]!=entry["recipient_id"]
        or evidence!=entry["receipt_sha256"]):
        return deny("handoff-entry-evidence-mismatch")
    # Signature/history verification can take time; do not return a success
    # against a ledger snapshot that changed while it was being checked.
    refreshed=inspect_entry(db,expected_head,minimum_receipts,sequence)
    if not refreshed["entry_valid"] or refreshed!=entry:
        return deny("handoff-entry-changed-during-verification")
    return _out(evidence_valid=True,state="pending-review",
                reason="reverified-signed-receipt-matches-pinned-local-entry",
                sequence=sequence,head_hash=entry["head_hash"],
                receipt_sha256=evidence)
