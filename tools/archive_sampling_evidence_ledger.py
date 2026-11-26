#!/usr/bin/env python3
"""Atomic local evidence ledger for independently challenged archive sampling.

Stores only signed-evidence digests and derived challenge nonces. Every
transaction rechecks the complete hash chain and nonce index before append.
A trusted external head and minimum count are needed to detect database rollback.
"""
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

_spec=importlib.util.spec_from_file_location(
    "palaco_sampling_ledger_multisample",
    Path(__file__).with_name("multi_sample_archive_availability.py"))
sampling=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sampling)

DOMAIN=b"PALACO-ARCHIVE-SAMPLING-LEDGER-V1\x00"
EVIDENCE_DOMAIN=b"PALACO-ARCHIVE-SAMPLING-EVIDENCE-V1\x00"
GENESIS="0"*64
MAX_BATCHES=10000


def _json(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")


def _out(**fields):
    return {"release_gate":"HOLD","authorization_granted":False,
            "automatic_restore":False,"recovery_approved":False,
            "recorded":False,"state":"quarantined",**fields}


def _hash(seq,manifest_hash,seed_hex,population,indices_json,nonce_json,
          evidence_hash,previous):
    return hashlib.sha256(DOMAIN+_json(
        [seq,manifest_hash,seed_hex,population,indices_json,nonce_json,
         evidence_hash,previous])).hexdigest()


def _schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS archive_sample_batches(
        sequence INTEGER PRIMARY KEY CHECK(sequence>0),
        manifest_sha256 TEXT NOT NULL,
        seed_hex TEXT NOT NULL,
        population INTEGER NOT NULL,
        indices_json TEXT NOT NULL,
        nonce_json TEXT NOT NULL,
        evidence_sha256 TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        UNIQUE(manifest_sha256,seed_hex))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS archive_sample_nonces(
        nonce_hex TEXT PRIMARY KEY,
        batch_sequence INTEGER NOT NULL,
        ordinal INTEGER NOT NULL,
        UNIQUE(batch_sequence,ordinal),
        FOREIGN KEY(batch_sequence) REFERENCES archive_sample_batches(sequence))""")


def _scan(conn):
    rows=conn.execute("""SELECT sequence,manifest_sha256,seed_hex,population,
        indices_json,nonce_json,evidence_sha256,previous_hash,event_hash
        FROM archive_sample_batches ORDER BY sequence LIMIT ?""",
        (MAX_BATCHES+1,)).fetchall()
    if len(rows)>MAX_BATCHES:
        return None
    all_nonces=conn.execute("""SELECT nonce_hex,batch_sequence,ordinal
        FROM archive_sample_nonces""").fetchall()
    expected=set()
    previous=GENESIS
    for seq,row in enumerate(rows,1):
        num,manifest,seed,population,indices_raw,nonces_raw,evidence,prior,digest=row
        if (type(num) is not int or num!=seq
            or any(not isinstance(x,str) or not sampling.single.HEX.fullmatch(x)
                   for x in (manifest,seed,evidence,prior,digest))
            or type(population) is not int or not 1<=population<=sampling.single.MAX_CHUNKS
            or prior!=previous):
            return None
        try:
            chosen=json.loads(indices_raw)
            nonces=json.loads(nonces_raw)
        except (TypeError,ValueError):
            return None
        if (not isinstance(chosen,list) or not isinstance(nonces,list)
            or not 1<=len(chosen)==len(nonces)<=sampling.MAX_SAMPLES
            or any(type(x) is not int or not 0<=x<sampling.single.MAX_CHUNKS for x in chosen)
            or len(set(chosen))!=len(chosen)
            or any(not isinstance(n,str) or not sampling.single.HEX.fullmatch(n)
                   for n in nonces)
            or len(set(nonces))!=len(nonces)):
            return None
        if chosen!=sampling.indices(seed,manifest,population,len(chosen)):
            return None
        if any(n!=sampling.nonce(seed,manifest,i) for i,n in enumerate(nonces)):
            return None
        expected.update((nonce,seq,i) for i,nonce in enumerate(nonces))
        if digest!=_hash(seq,manifest,seed,population,indices_raw,nonces_raw,evidence,prior):
            return None
        previous=digest
    if len(expected)!=sum(len(json.loads(row[4])) for row in rows):
        return None
    if expected!=set(all_nonces):
        return None
    return {"batches":len(rows),"head_hash":previous,"used_nonces":{x[0] for x in expected}}


def _path(db):
    if not isinstance(db,(str,Path)) or str(db)==":memory:":
        raise ValueError("persistent-ledger-required")
    target=Path(db)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise ValueError("invalid-ledger-file")
    return target


def record(db,manifest,manifest_pin,archive_head,seed,count,min_coverage,
           challenges,replies,requester,now,roots,allowed,revoked,
           expected_previous_head,minimum_existing_batches):
    def deny(reason):return _out(reason=reason)
    if (not isinstance(expected_previous_head,str)
        or not sampling.single.HEX.fullmatch(expected_previous_head)
        or type(minimum_existing_batches) is not int
        or not 0<=minimum_existing_batches<=MAX_BATCHES):
        return deny("missing-independent-previous-ledger-pin")
    try: target=_path(db)
    except ValueError as exc:return deny(str(exc))
    try:
        with sqlite3.connect(target,timeout=5) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _schema(conn)
            state=_scan(conn)
            if state is None:
                return deny("sampling-ledger-integrity-failed")
            if state["batches"]<minimum_existing_batches:
                return deny("sampling-ledger-rollback")
            if state["head_hash"]!=expected_previous_head:
                return deny("sampling-ledger-head-mismatch")
            if state["batches"]>=MAX_BATCHES:
                return deny("sampling-ledger-full")
            checked=sampling.verify(
                manifest,manifest_pin,archive_head,seed,count,min_coverage,
                challenges,replies,requester,now,state["used_nonces"],
                roots,allowed,revoked)
            if not checked["multi_sample_valid"]:
                return deny(checked["reason"])
            chosen=checked["sampled_indices"]
            nonces=[sampling.nonce(seed,manifest_pin,i) for i in range(len(chosen))]
            evidence=hashlib.sha256(EVIDENCE_DOMAIN+_json({
                "manifest":manifest,"seed":seed,"challenges":challenges,
                "replies":replies,"requester":requester})).hexdigest()
            seq=state["batches"]+1
            index_json=_json(chosen).decode()
            nonce_json=_json(nonces).decode()
            event=_hash(seq,manifest_pin,seed,len(manifest["chunk_sha256"]),index_json,nonce_json,evidence,
                        state["head_hash"])
            conn.execute("INSERT INTO archive_sample_batches VALUES(?,?,?,?,?,?,?,?,?)",
                         (seq,manifest_pin,seed,len(manifest["chunk_sha256"]),
                          index_json,nonce_json,evidence,state["head_hash"],event))
            for ordinal,nonce in enumerate(nonces):
                conn.execute("INSERT INTO archive_sample_nonces VALUES(?,?,?)",
                             (nonce,seq,ordinal))
    except (sqlite3.Error,ValueError,TypeError,OverflowError,OSError) as exc:
        return deny("sampling-ledger-transaction-failed")
    return {**_out(),"recorded":True,"state":"pending-review",
            "reason":"locally-indexed-verified-sample-evidence-not-remote-custody",
            "batches":seq,"head_hash":event,
            "evidence_sha256":evidence,"sample_count":len(nonces)}


def inspect(db,expected_head,minimum_batches):
    def deny(reason):
        return {**_out(),"ledger_valid":False,"reason":reason}
    if (not isinstance(expected_head,str) or not sampling.single.HEX.fullmatch(expected_head)
        or type(minimum_batches) is not int or not 1<=minimum_batches<=MAX_BATCHES):
        return deny("missing-independent-sampling-ledger-pin")
    try: target=_path(db)
    except ValueError as exc:return deny(str(exc))
    if not target.is_file():return deny("missing-sampling-ledger")
    try:
        conn=sqlite3.connect(target.resolve().as_uri()+"?mode=ro",uri=True)
        try:
            conn.execute("BEGIN")
            state=_scan(conn)
            conn.commit()
        finally:
            conn.close()
    except (sqlite3.Error,TypeError,ValueError,OSError):
        return deny("unreadable-sampling-ledger")
    if state is None:return deny("sampling-ledger-integrity-failed")
    if state["batches"]<minimum_batches:return deny("sampling-ledger-rollback")
    if state["head_hash"]!=expected_head:return deny("sampling-ledger-head-mismatch")
    return {**_out(),"ledger_valid":True,"state":"pending-review",
            "reason":"local-sampling-ledger-matches-independent-anchor",
            "batches":state["batches"],"head_hash":state["head_hash"]}
