"""Independent A1 envelope verifier. Python standard library only; no Rust imports."""
import hashlib
import json
import re
import sys

MAX_BYTES = 1_048_576
MAX_INT = 9_007_199_254_740_991
KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_:./-]{1,128}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_KEYS = set("schema_version citadel_id world_id purpose edition presentation lifecycle canonical_encoding cryptographic_profile manifest_digest".split())
RECORD_KEYS = set("record_id record_type schema_version citadel_id world_id sequence previous_digest payload_digest provenance_refs evidence_refs authorization_ref epistemic_state created_at_display trusted_time_evidence actor_ref signature record_digest manifest_digest payload".split())
TYPES = set("QuestionRecord EvidenceObject EpistemicAssessment DecisionThreshold DecisionRecord AuthorizationRecord ConsequenceRecord ReassessmentRecord RevocationEvent ProofLifecycleEvent".split())
STATES = set("UNKNOWN SUPPORTED CONTESTED INSUFFICIENT REFUTED".split())

def blank(value):
    # Frozen A1 code points, independent of language/runtime Unicode tables.
    return all(ord(c) <= 0x20 or ord(c) in (0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000) or 0x2000 <= ord(c) <= 0x200a for c in value)

def reject(_):
    raise ValueError("non-integer JSON number")

def integer(value):
    if value == '-0':
        raise ValueError('negative zero forbidden')
    return int(value)

def pairs(items):
    result = {}
    for key, value in items:
        if not KEY.fullmatch(key) or key in result:
            raise ValueError("invalid or duplicate key")
        result[key] = value
    return result

def validate_json(value, depth=0):
    if depth > 64:
        raise ValueError("nesting exceeds 64")
    if isinstance(value, dict):
        for key, item in value.items():
            if not KEY.fullmatch(key):
                raise ValueError("invalid key")
            validate_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            validate_json(item, depth + 1)
    elif isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif type(value) is int:
        if abs(value) > MAX_INT:
            raise ValueError("integer outside safe range")
    elif value is not None and type(value) is not bool:
        raise ValueError("unsupported JSON type")

def canonical(value):
    validate_json(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(domain, value):
    if domain not in ("MANIFEST", "PAYLOAD", "RECORD"):
        raise ValueError("unknown domain")
    return hashlib.sha256(f"PALACO:CITADEL:{domain}:A1\0".encode("ascii") + canonical(value)).hexdigest()

def without(value, key):
    return {k: v for k, v in value.items() if k != key}

def receipt(result, reason):
    return dict(result=result, reason=reason, scope="A1_ENVELOPE_INTEGRITY", identity="UNKNOWN", authority="UNKNOWN", current_validity="UNKNOWN", signatures="UNKNOWN", archive_inclusion="UNKNOWN")

def verify(raw, expected_manifest, expected_head):
    try:
        if len(raw) > MAX_BYTES:
            raise ValueError("size")
        bundle = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject, parse_int=integer)
        validate_json(bundle)
    except (ValueError, UnicodeError, RecursionError):
        return receipt("INVALID", "MALFORMED_JSON_PROFILE")
    if not isinstance(bundle, dict):
        return receipt("INVALID", "BUNDLE_OBJECT_REQUIRED")
    if set(bundle) != {"manifest", "records"}:
        return receipt("INVALID", "BUNDLE_FIELDS")
    m = bundle["manifest"]
    if not isinstance(m, dict) or set(m) != MANIFEST_KEYS or any(not isinstance(m[k], str) for k in MANIFEST_KEYS - {"presentation"}) or not isinstance(m["presentation"], list) or any(not isinstance(x, str) for x in m["presentation"]):
        return receipt("INVALID", "MANIFEST_SCHEMA")
    if (m["schema_version"], m["canonical_encoding"], m["cryptographic_profile"], m["lifecycle"]) != ("0.1", "PALACO-JSON-A1", "SHA256-DOMAIN-A1", "DRAFT"):
        return receipt("UNKNOWN", "UNSUPPORTED_MANIFEST_PROFILE")
    if not IDENTIFIER.fullmatch(m["citadel_id"]) or not IDENTIFIER.fullmatch(m["world_id"]) or blank(m["purpose"]) or blank(m["edition"]) or not m["presentation"] or any(blank(s) for s in m["presentation"]) or not DIGEST.fullmatch(m["manifest_digest"]):
        return receipt("INVALID", "MANIFEST_FIELDS")
    if digest("MANIFEST", without(m, "manifest_digest")) != m["manifest_digest"]:
        return receipt("INVALID", "MANIFEST_DIGEST")
    if not expected_manifest or not expected_head:
        return receipt("INCOMPLETE", "EXTERNAL_ANCHORS_REQUIRED")
    if not DIGEST.fullmatch(expected_manifest) or not DIGEST.fullmatch(expected_head):
        return receipt("INVALID", "ANCHOR_FORMAT")
    if m["manifest_digest"] != expected_manifest:
        return receipt("CONFLICT", "MANIFEST_ANCHOR_CONFLICT")
    records = bundle["records"]
    if not isinstance(records, list):
        return receipt("INVALID", "RECORDS_ARRAY_REQUIRED")
    if not records:
        return receipt("UNKNOWN", "NO_RECORDS")
    ids, sequences, previous, signed = {}, set(), None, False
    string_fields = RECORD_KEYS - {"sequence", "previous_digest", "provenance_refs", "evidence_refs", "authorization_ref", "trusted_time_evidence", "signature", "payload"}
    for index, r in enumerate(records, 1):
        if not isinstance(r, dict) or set(r) != RECORD_KEYS:
            return receipt("INVALID", "ENVELOPE_FIELDS")
        if any(not isinstance(r[k], str) for k in string_fields) or type(r["sequence"]) is not int or r["sequence"] < 0:
            return receipt("INVALID", "ENVELOPE_SCHEMA")
        if any(r[k] is not None and not isinstance(r[k], str) for k in ("previous_digest", "authorization_ref", "trusted_time_evidence")) or any(not isinstance(r[k], list) or any(not isinstance(x, str) for x in r[k]) for k in ("provenance_refs", "evidence_refs")):
            return receipt("INVALID", "ENVELOPE_SCHEMA")
        if r["schema_version"] != "0.1":
            return receipt("UNKNOWN", "UNSUPPORTED_RECORD_VERSION")
        if not IDENTIFIER.fullmatch(r["record_id"]) or not IDENTIFIER.fullmatch(r["actor_ref"]) or not isinstance(r["payload"], dict) or blank(r["created_at_display"]) or not DIGEST.fullmatch(r["record_digest"]) or not DIGEST.fullmatch(r["payload_digest"]) or (r["previous_digest"] is not None and not DIGEST.fullmatch(r["previous_digest"])):
            return receipt("INVALID", "ENVELOPE_VALUES")
        if r["record_type"] not in TYPES or r["epistemic_state"] not in STATES:
            return receipt("INVALID", "ENVELOPE_ENUM")
        if any(r[k] != m[k] for k in ("citadel_id", "world_id", "manifest_digest")):
            return receipt("CONFLICT", "RESOURCE_CONTEXT_CONFLICT")
        if r["record_id"] in ids or r["sequence"] in sequences:
            return receipt("CONFLICT", "DUPLICATE_ID_OR_SEQUENCE")
        sequences.add(r["sequence"])
        if r["sequence"] > index:
            return receipt("INCOMPLETE", "SEQUENCE_GAP")
        if r["sequence"] != index or r["previous_digest"] != previous:
            return receipt("INVALID", "CHAIN_ORDER")
        if digest("PAYLOAD", r["payload"]) != r["payload_digest"] or digest("RECORD", without(r, "record_digest")) != r["record_digest"]:
            return receipt("INVALID", "RECORD_DIGEST")
        references = r["provenance_refs"] + r["evidence_refs"] + [r[k] for k in ("authorization_ref", "trusted_time_evidence") if r[k] is not None]
        for ref in references:
            if not IDENTIFIER.fullmatch(ref):
                return receipt("INVALID", "REFERENCE_FORMAT")
            if ref == r["record_id"]:
                return receipt("INVALID", "SELF_REFERENCE")
            if ref not in ids:
                return receipt("INCOMPLETE", "DEPENDENCY_MISSING_OR_NOT_PRIOR")
        if any(ids[x] != "EvidenceObject" for x in r["evidence_refs"]) or (r["authorization_ref"] is not None and ids[r["authorization_ref"]] != "AuthorizationRecord"):
            return receipt("INVALID", "REFERENCE_TYPE")
        if any(len(set(r[k])) != len(r[k]) for k in ("provenance_refs", "evidence_refs")):
            return receipt("INVALID", "DUPLICATE_REFERENCE")
        ids[r["record_id"]] = r["record_type"]
        previous = r["record_digest"]
        signed |= r["signature"] is not None
    if previous != expected_head:
        return receipt("INCOMPLETE", "ANCHORED_HEAD_NOT_PRESENT")
    if signed:
        return receipt("UNKNOWN", "SIGNATURE_PROFILE_NOT_IMPLEMENTED")
    return receipt("VALID", "A1_INTEGRITY_MATCHES_EXTERNAL_ANCHORS")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: verify.py BUNDLE EXPECTED_MANIFEST_DIGEST EXPECTED_HEAD_DIGEST", file=sys.stderr)
        sys.exit(64)
    try:
        with open(sys.argv[1], "rb") as source:
            data = source.read(MAX_BYTES + 1)
    except OSError:
        print("cannot read bundle", file=sys.stderr)
        sys.exit(66)
    result = verify(data, sys.argv[2], sys.argv[3])
    print(json.dumps(result))
    sys.exit(0 if result["result"] == "VALID" else 1)

