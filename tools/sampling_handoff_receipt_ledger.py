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
    # Unlike quick_check, integrity_check also verifies UNIQUE constraints
    # and index/table consistency. One returned error is sufficient to deny.
    return (conn.execute("PRAGMA integrity_check(1)").fetchone()==("ok",)
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
            # SQLite disables FK enforcement by default on many connections.
            # Enable it before BEGIN: setting it inside a transaction is inert.
            conn.execute("PRAGMA foreign_keys=ON")
            if conn.execute("PRAGMA foreign_keys").fetchone()!=(1,):
                return deny("handoff-receipt-foreign-keys-unavailable")
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


MANIFEST_DOMAIN=b"PALACO-SAMPLING-HANDOFF-LEDGER-MANIFEST-V1\x00"


def export_review_manifest(db,expected_head,minimum_receipts):
    """Export a bounded read-only receipt index against a trusted ledger pin.

    The manifest is a local review artifact, not a signed independent anchor.
    """
    def deny(reason):return _out(manifest_exported=False,reason=reason)
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
            if state is None:
                return deny("handoff-receipt-ledger-integrity-failed")
            if state["receipts"]<minimum_receipts:
                return deny("handoff-receipt-ledger-rollback")
            if state["head_hash"]!=expected_head:
                return deny("handoff-receipt-ledger-head-mismatch")
            rows=conn.execute("""SELECT sequence,recipient_id,recipient_key_id,
                package_sha256,nonce_hex,receipt_sha256,previous_hash,event_hash
                FROM sampling_handoff_receipts ORDER BY sequence LIMIT ?""",
                (MAX_RECORDS+1,)).fetchall()
            if len(rows)!=state["receipts"]:
                return deny("handoff-receipt-ledger-changed-during-export")
            entries=[dict(zip(("sequence","recipient_id","recipient_key_id",
                "package_sha256","receipt_nonce_hex","receipt_sha256",
                "previous_hash","event_hash"),row)) for row in rows]
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error,TypeError,ValueError,OverflowError,OSError):
        return deny("unreadable-handoff-receipt-ledger")
    manifest={"schema_version":"0.1.0","receipt_count":state["receipts"],
              "head_hash":state["head_hash"],"entries":entries}
    digest=hashlib.sha256(
        MANIFEST_DOMAIN+json.dumps(manifest,sort_keys=True,
        separators=(",",":"),ensure_ascii=False,allow_nan=False
        ).encode("utf-8")).hexdigest()
    return _out(manifest_exported=True,state="pending-review",
                reason="local-review-manifest-not-independent-custody",
                manifest=manifest,manifest_sha256=digest)


MANIFEST_FIELDS={"schema_version","receipt_count","head_hash","entries"}
MANIFEST_ENTRY_FIELDS={"sequence","recipient_id","recipient_key_id",
    "package_sha256","receipt_nonce_hex","receipt_sha256",
    "previous_hash","event_hash"}


def verify_review_manifest(manifest,expected_manifest_sha256,
                           expected_head,minimum_receipts):
    """Offline validation of a reviewer manifest against independent pins.

    No database or network access. The caller must authenticate the pins.
    """
    def deny(reason):return _out(manifest_valid=False,reason=reason)
    if (not all(isinstance(value,str) and handoff.HEX.fullmatch(value)
                for value in (expected_manifest_sha256,expected_head))
        or type(minimum_receipts) is not int
        or not 1<=minimum_receipts<=MAX_RECORDS):
        return deny("missing-independent-manifest-pins")
    if not isinstance(manifest,dict) or set(manifest)!=MANIFEST_FIELDS:
        return deny("invalid-review-manifest-schema")
    if (manifest["schema_version"]!="0.1.0"
        or type(manifest["receipt_count"]) is not int
        or not 1<=manifest["receipt_count"]<=MAX_RECORDS
        or not isinstance(manifest["entries"],list)
        or len(manifest["entries"])!=manifest["receipt_count"]
        or not isinstance(manifest["head_hash"],str)
        or not handoff.HEX.fullmatch(manifest["head_hash"])):
        return deny("invalid-review-manifest-schema")
    if manifest["receipt_count"]<minimum_receipts:
        return deny("review-manifest-rollback")
    if manifest["head_hash"]!=expected_head:
        return deny("review-manifest-head-mismatch")
    previous=GENESIS
    nonces=set()
    package_bindings=set()
    for sequence,entry in enumerate(manifest["entries"],1):
        if not isinstance(entry,dict) or set(entry)!=MANIFEST_ENTRY_FIELDS:
            return deny("invalid-review-manifest-entry")
        if (type(entry["sequence"]) is not int
            or entry["sequence"]!=sequence
            or not isinstance(entry["recipient_id"],str)
            or not handoff.IDENT.fullmatch(entry["recipient_id"])):
            return deny("invalid-review-manifest-entry")
        fields=("recipient_key_id","package_sha256","receipt_nonce_hex",
                "receipt_sha256","previous_hash","event_hash")
        if any(not isinstance(entry[field],str)
               or not handoff.HEX.fullmatch(entry[field]) for field in fields):
            return deny("invalid-review-manifest-entry")
        nonce=entry["receipt_nonce_hex"]
        binding=(entry["recipient_key_id"],entry["package_sha256"])
        if (entry["previous_hash"]!=previous
            or nonce in nonces or binding in package_bindings
            or entry["event_hash"]!=_digest(
                sequence,entry["recipient_id"],entry["recipient_key_id"],
                entry["package_sha256"],nonce,entry["receipt_sha256"],
                previous)):
            return deny("review-manifest-chain-invalid")
        nonces.add(nonce)
        package_bindings.add(binding)
        previous=entry["event_hash"]
    if previous!=expected_head:
        return deny("review-manifest-chain-head-mismatch")
    try:
        computed=hashlib.sha256(
            MANIFEST_DOMAIN+json.dumps(manifest,sort_keys=True,
            separators=(",",":"),ensure_ascii=False,allow_nan=False
            ).encode("utf-8")).hexdigest()
    except (TypeError,ValueError,OverflowError,UnicodeError):
        return deny("invalid-review-manifest-encoding")
    if computed!=expected_manifest_sha256:
        return deny("review-manifest-digest-mismatch")
    return _out(manifest_valid=True,state="pending-review",
                reason="offline-manifest-matches-independent-pins-not-custody",
                receipts=manifest["receipt_count"],head_hash=expected_head,
                manifest_sha256=computed)


def verify_manifest_succession(previous_manifest,previous_sha256,
                              previous_head,current_manifest,current_sha256,
                              current_head,minimum_previous_receipts):
    """Compare two independently pinned offline manifests for append-only growth.

    Each manifest must pass its own full offline integrity check first.
    This proves relative consistency, not trust in either external pin.
    """
    def deny(reason):return _out(succession_valid=False,reason=reason)
    before=verify_review_manifest(
        previous_manifest,previous_sha256,previous_head,
        minimum_previous_receipts)
    if not before["manifest_valid"]:
        return deny("previous-"+before["reason"])
    after=verify_review_manifest(
        current_manifest,current_sha256,current_head,
        previous_manifest["receipt_count"])
    if not after["manifest_valid"]:
        return deny("current-"+after["reason"])
    count=previous_manifest["receipt_count"]
    if current_manifest["entries"][:count]!=previous_manifest["entries"]:
        return deny("review-manifest-history-rewritten")
    if current_manifest["receipt_count"]==count:
        return _out(succession_valid=True,state="pending-review",
                    reason="identical-pinned-review-manifests-no-new-receipts",
                    previous_receipts=count,current_receipts=count,
                    head_hash=current_head)
    if current_manifest["entries"][count]["previous_hash"]!=previous_head:
        return deny("review-manifest-succession-link-invalid")
    return _out(succession_valid=True,state="pending-review",
                reason="offline-manifest-append-only-succession-not-custody",
                previous_receipts=count,
                current_receipts=current_manifest["receipt_count"],
                head_hash=current_head)


DELTA_DOMAIN=b"PALACO-SAMPLING-HANDOFF-MANIFEST-DELTA-V1\x00"
DELTA_FIELDS={"schema_version","previous_head","previous_receipts",
              "current_head","current_receipts","entries"}


def _manifest_hash(manifest):
    return hashlib.sha256(
        MANIFEST_DOMAIN+json.dumps(manifest,sort_keys=True,
        separators=(",",":"),ensure_ascii=False,allow_nan=False
        ).encode("utf-8")).hexdigest()


def _delta_hash(delta):
    return hashlib.sha256(
        DELTA_DOMAIN+json.dumps(delta,sort_keys=True,
        separators=(",",":"),ensure_ascii=False,allow_nan=False
        ).encode("utf-8")).hexdigest()


def create_review_delta(previous_manifest,previous_sha256,previous_head,
                        current_manifest,current_sha256,current_head,
                        minimum_previous_receipts):
    """Build a compact review-only append from two fully pinned manifests."""
    def deny(reason):return _out(delta_created=False,reason=reason)
    check=verify_manifest_succession(
        previous_manifest,previous_sha256,previous_head,
        current_manifest,current_sha256,current_head,minimum_previous_receipts)
    if not check["succession_valid"]:return deny(check["reason"])
    prior=previous_manifest["receipt_count"]
    delta={"schema_version":"0.1.0","previous_head":previous_head,
           "previous_receipts":prior,"current_head":current_head,
           "current_receipts":current_manifest["receipt_count"],
           "entries":current_manifest["entries"][prior:]}
    return _out(delta_created=True,state="pending-review",
                reason="pinned-review-delta-not-custody",
                delta=delta,delta_sha256=_delta_hash(delta))


def verify_review_delta(previous_manifest,previous_sha256,previous_head,
                        delta,expected_delta_sha256,expected_current_head,
                        minimum_previous_receipts):
    """Verify an independently pinned append without the full new manifest.

    Requires the independently authenticated previous manifest and both
    external delta/current-head pins. This does not verify signatures.
    """
    def deny(reason):return _out(delta_valid=False,reason=reason)
    prior=verify_review_manifest(previous_manifest,previous_sha256,
                                 previous_head,minimum_previous_receipts)
    if not prior["manifest_valid"]:return deny("previous-"+prior["reason"])
    if (not isinstance(expected_delta_sha256,str)
        or not handoff.HEX.fullmatch(expected_delta_sha256)
        or not isinstance(expected_current_head,str)
        or not handoff.HEX.fullmatch(expected_current_head)):
        return deny("missing-independent-delta-pins")
    if not isinstance(delta,dict) or set(delta)!=DELTA_FIELDS:
        return deny("invalid-review-delta-schema")
    count=previous_manifest["receipt_count"]
    if (delta["schema_version"]!="0.1.0"
        or type(delta["previous_receipts"]) is not int
        or type(delta["current_receipts"]) is not int
        or delta["previous_receipts"]!=count
        or not count<=delta["current_receipts"]<=MAX_RECORDS
        or not isinstance(delta["entries"],list)
        or len(delta["entries"])!=delta["current_receipts"]-count
        or type(delta["previous_head"]) is not str
        or type(delta["current_head"]) is not str
        or delta["previous_head"]!=previous_head
        or delta["current_head"]!=expected_current_head):
        return deny("invalid-review-delta-schema-or-pins")
    # Validate scalar shapes before serializing untrusted delta content.
    # This also bounds each field's size before constructing its digest.
    hex_fields=("recipient_key_id","package_sha256","receipt_nonce_hex",
                "receipt_sha256","previous_hash","event_hash")
    for sequence,entry in enumerate(delta["entries"],count+1):
        if (type(entry) is not dict or set(entry)!=MANIFEST_ENTRY_FIELDS):
            return deny("invalid-review-delta-entry")
        if (type(entry["sequence"]) is not int
            or entry["sequence"]!=sequence
            or type(entry["recipient_id"]) is not str
            or not handoff.IDENT.fullmatch(entry["recipient_id"])
            or any(type(entry[field]) is not str
                   or not handoff.HEX.fullmatch(entry[field])
                   for field in hex_fields)):
            return deny("invalid-review-delta-entry")
    try:computed=_delta_hash(delta)
    except (TypeError,ValueError,OverflowError,UnicodeError):
        return deny("invalid-review-delta-encoding")
    if computed!=expected_delta_sha256:
        return deny("review-delta-digest-mismatch")
    current={"schema_version":"0.1.0",
             "receipt_count":delta["current_receipts"],
             "head_hash":expected_current_head,
             "entries":previous_manifest["entries"]+delta["entries"]}
    try:current_sha256=_manifest_hash(current)
    except (TypeError,ValueError,OverflowError,UnicodeError):
        return deny("invalid-review-delta-encoding")
    checked=verify_manifest_succession(
        previous_manifest,previous_sha256,previous_head,
        current,current_sha256,expected_current_head,minimum_previous_receipts)
    if not checked["succession_valid"]:return deny(checked["reason"])
    return _out(delta_valid=True,state="pending-review",
                reason="offline-pinned-manifest-delta-not-custody",
                previous_receipts=count,
                current_receipts=delta["current_receipts"],
                head_hash=expected_current_head,
                current_manifest_sha256=current_sha256,
                delta_sha256=computed)


def verify_review_delta_with_manifest_pin(
        previous_manifest,previous_sha256,previous_head,
        delta,expected_delta_sha256,expected_current_head,
        expected_current_manifest_sha256,minimum_previous_receipts):
    """Strict delta verification with an independent reconstructed-manifest pin.

    The expected current manifest digest must be authenticated separately
    from the delta. The weaker legacy verifier remains review-only.
    """
    def deny(reason):return _out(delta_valid=False,reason=reason)
    if (not isinstance(expected_current_manifest_sha256,str)
        or not handoff.HEX.fullmatch(expected_current_manifest_sha256)):
        return deny("missing-independent-current-manifest-pin")
    checked=verify_review_delta(
        previous_manifest,previous_sha256,previous_head,
        delta,expected_delta_sha256,expected_current_head,
        minimum_previous_receipts)
    if not checked["delta_valid"]:
        return deny(checked["reason"])
    if checked["current_manifest_sha256"]!=expected_current_manifest_sha256:
        return deny("current-review-manifest-pin-mismatch")
    return _out(delta_valid=True,state="pending-review",
                reason="independently-pinned-offline-delta-not-custody",
                previous_receipts=checked["previous_receipts"],
                current_receipts=checked["current_receipts"],
                head_hash=expected_current_head,
                current_manifest_sha256=expected_current_manifest_sha256,
                delta_sha256=checked["delta_sha256"])


def assess_review_delta_fork(previous_manifest,previous_sha256,previous_head,
                             left_delta,left_delta_sha256,left_head,left_manifest_sha256,
                             right_delta,right_delta_sha256,right_head,right_manifest_sha256,
                             minimum_previous_receipts):
    """Compare two independently pinned deltas from the same trusted history.

    This is a conflict assessment, NEVER a choice of a canonical successor.
    """
    def deny(reason):return _out(assessment_valid=False,fork_detected=False,
                                 reason=reason)
    left=verify_review_delta_with_manifest_pin(
        previous_manifest,previous_sha256,previous_head,
        left_delta,left_delta_sha256,left_head,left_manifest_sha256,
        minimum_previous_receipts)
    if not left["delta_valid"]:
        return deny("left-"+left["reason"])
    right=verify_review_delta_with_manifest_pin(
        previous_manifest,previous_sha256,previous_head,
        right_delta,right_delta_sha256,right_head,right_manifest_sha256,
        minimum_previous_receipts)
    if not right["delta_valid"]:
        return deny("right-"+right["reason"])
    left_entries=left_delta["entries"]
    right_entries=right_delta["entries"]
    shared=min(len(left_entries),len(right_entries))
    if left_entries[:shared]!=right_entries[:shared]:
        first=next(i for i in range(shared)
                   if left_entries[i]!=right_entries[i])
        # A local commitment to the conflict evidence, not an independent
        # witness signature or an authorization to resolve the split.
        evidence={
            "schema_version":"0.1.0",
            "previous_manifest_sha256":previous_sha256,
            "previous_head":previous_head,
            "first_divergent_sequence":previous_manifest["receipt_count"]+first+1,
            "left_delta_sha256":left_delta_sha256,
            "right_delta_sha256":right_delta_sha256,
            "left_manifest_sha256":left_manifest_sha256,
            "right_manifest_sha256":right_manifest_sha256,
            "left_head":left_head,
            "right_head":right_head,
            "left_event_hash":left_entries[first]["event_hash"],
            "right_event_hash":right_entries[first]["event_hash"]
        }
        encoded=json.dumps(evidence,sort_keys=True,separators=(",",":"),
                           ensure_ascii=False,allow_nan=False).encode("utf-8")
        evidence_sha256=hashlib.sha256(
            b"PALACO-SAMPLING-HANDOFF-FORK-EVIDENCE-V1\x00"+encoded).hexdigest()
        return _out(assessment_valid=True,fork_detected=True,
                    reason="conflicting-independently-pinned-delta-branches",
                    left_head=left_head,right_head=right_head,
                    previous_head=previous_head,
                    fork_evidence=evidence,fork_evidence_sha256=evidence_sha256)
    if len(left_entries)==len(right_entries):
        return _out(assessment_valid=True,fork_detected=False,
                    state="pending-review",
                    reason="identical-independently-pinned-delta-branches",
                    head_hash=left_head)
    return _out(assessment_valid=True,fork_detected=False,
                state="pending-review",
                reason="prefix-compatible-delta-branches-not-custody",
                shorter_receipts=min(left["current_receipts"],
                                     right["current_receipts"]),
                longer_receipts=max(left["current_receipts"],
                                    right["current_receipts"]))


FORK_EVIDENCE_DOMAIN=b"PALACO-SAMPLING-HANDOFF-FORK-EVIDENCE-V1\x00"


def verify_review_fork_evidence(
        previous_manifest,previous_sha256,previous_head,
        left_delta,left_delta_sha256,left_head,left_manifest_sha256,
        right_delta,right_delta_sha256,right_head,right_manifest_sha256,
        minimum_previous_receipts,evidence,expected_evidence_sha256):
    """Independently recompute a pinned conflict assessment; never release it.

    Reverification is offline. The evidence SHA-256 and all manifest/delta
    pins must originate from authenticated external review channels.
    """
    def deny(reason):return _out(fork_evidence_valid=False,
                                 fork_detected=False,reason=reason)
    if (not isinstance(expected_evidence_sha256,str)
        or not handoff.HEX.fullmatch(expected_evidence_sha256)):
        return deny("missing-independent-fork-evidence-pin")
    assessment=assess_review_delta_fork(
        previous_manifest,previous_sha256,previous_head,
        left_delta,left_delta_sha256,left_head,left_manifest_sha256,
        right_delta,right_delta_sha256,right_head,right_manifest_sha256,
        minimum_previous_receipts)
    if not assessment["assessment_valid"]:
        return deny("fork-assessment-"+assessment["reason"])
    if not assessment["fork_detected"]:
        return deny("no-conflicting-review-delta-branches")
    if not isinstance(evidence,dict) or evidence!=assessment["fork_evidence"]:
        return deny("fork-evidence-does-not-match-verified-branches")
    encoded=json.dumps(assessment["fork_evidence"],sort_keys=True,
                       separators=(",",":"),ensure_ascii=False,
                       allow_nan=False).encode("utf-8")
    computed=hashlib.sha256(FORK_EVIDENCE_DOMAIN+encoded).hexdigest()
    if computed!=expected_evidence_sha256:
        return deny("fork-evidence-pin-mismatch")
    return _out(fork_evidence_valid=True,fork_detected=True,
                reason="reverified-conflicting-branches-remain-quarantined",
                fork_evidence_sha256=computed,
                first_divergent_sequence=evidence["first_divergent_sequence"])


MAX_DELTA_JSON_BYTES=8*1024*1024


def _unique_json_object(pairs):
    """Reject ambiguous duplicate JSON field names at every nesting level."""
    obj={}
    for key,value in pairs:
        if key in obj:
            raise ValueError("duplicate-review-delta-json-key")
        obj[key]=value
    return obj


def _reject_json_constant(value):
    raise ValueError("non-finite-review-delta-json-number")


def _bounded_json_integer(value):
    """Only bounded decimal integers are permissible in delta metadata."""
    if len(value)>10:
        raise ValueError("oversized-review-delta-json-integer")
    return int(value)


def _reject_json_float(value):
    """This schema has no floating-point fields; reject them in the parser."""
    raise ValueError("floating-point-review-delta-json-number")


def verify_review_delta_json(previous_manifest,previous_sha256,previous_head,
                             raw_delta,expected_delta_sha256,
                             expected_current_head,minimum_previous_receipts):
    """Bound and strictly decode untrusted JSON bytes before delta checks.

    Caller-supplied external pins remain mandatory; no database access.
    """
    def deny(reason):return _out(delta_valid=False,reason=reason)
    if type(raw_delta) is not bytes:
        return deny("invalid-review-delta-json-type")
    if not 1<=len(raw_delta)<=MAX_DELTA_JSON_BYTES:
        return deny("review-delta-json-size-limit")
    try:
        delta=json.loads(raw_delta.decode("utf-8"),
                         object_pairs_hook=_unique_json_object,
                         parse_constant=_reject_json_constant,
                         parse_int=_bounded_json_integer,
                         parse_float=_reject_json_float)
    except (UnicodeError,ValueError,TypeError,RecursionError):
        return deny("invalid-or-ambiguous-review-delta-json")
    return verify_review_delta(
        previous_manifest,previous_sha256,previous_head,
        delta,expected_delta_sha256,expected_current_head,
        minimum_previous_receipts)
