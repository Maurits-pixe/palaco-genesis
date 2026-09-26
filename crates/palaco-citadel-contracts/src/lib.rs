//! EVA-LA-001 A1: deterministic record integrity, never identity or authority.
#![forbid(unsafe_code)]

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// The maximum input size accepted by the standalone A1 verifier.
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const ENCODING: &str = "PALACO-JSON-A1";
const HASH_PROFILE: &str = "SHA256-DOMAIN-A1";
const RECORD_KEYS: &[&str] = &[
    "record_id",
    "record_type",
    "schema_version",
    "citadel_id",
    "world_id",
    "sequence",
    "previous_digest",
    "payload_digest",
    "provenance_refs",
    "evidence_refs",
    "authorization_ref",
    "epistemic_state",
    "created_at_display",
    "trusted_time_evidence",
    "actor_ref",
    "signature",
    "record_digest",
    "manifest_digest",
    "payload",
];

/// Versioned Citadel identity/configuration. It is not an activation grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitadelManifest {
    schema_version: String,
    citadel_id: String,
    world_id: String,
    purpose: String,
    edition: String,
    presentation: Vec<String>,
    lifecycle: String,
    canonical_encoding: String,
    cryptographic_profile: String,
    manifest_digest: String,
}

/// A1 record envelope; payload semantics are reserved for later domain contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRecordEnvelope {
    record_id: String,
    record_type: String,
    schema_version: String,
    citadel_id: String,
    world_id: String,
    sequence: u64,
    previous_digest: Option<String>,
    payload_digest: String,
    provenance_refs: Vec<String>,
    evidence_refs: Vec<String>,
    authorization_ref: Option<String>,
    epistemic_state: String,
    created_at_display: String,
    trusted_time_evidence: Option<String>,
    actor_ref: String,
    signature: Option<Value>,
    record_digest: String,
    manifest_digest: String,
    payload: Value,
}

/// Scoped integrity outcome. Only `Valid` passes the A1 integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationResult {
    /// Supplied records match the external anchors within the A1 scope.
    Valid,
    /// Malformed data, mismatched digests or invalid ordering.
    Invalid,
    /// A required anchor, chain segment or referenced dependency is absent.
    Incomplete,
    /// Duplicate identities/sequences or a mismatching manifest anchor.
    Conflict,
    /// No records or an unsupported profile/signature/lifecycle.
    Unknown,
}

/// Receipt deliberately separates integrity from identity, authority and time.
#[derive(Debug, Serialize)]
pub struct VerificationReceipt {
    /// A1-scoped result, not a full Citadel verification result.
    pub result: VerificationResult,
    /// Machine-readable reason for this result.
    pub reason: String,
    /// The only verification scope implemented by this component.
    pub scope: &'static str,
    /// Actor identities are not verified by a digest check.
    pub identity: &'static str,
    /// No authorization or constitutional authority is inferred.
    pub authority: &'static str,
    /// Wall-clock labels and historical records do not prove current validity.
    pub current_validity: &'static str,
    /// A1 does not validate signatures.
    pub signatures: &'static str,
    /// A1 does not validate ArchiveRoot inclusion proofs.
    pub archive_inclusion: &'static str,
}

fn receipt(result: VerificationResult, reason: &str) -> VerificationReceipt {
    VerificationReceipt {
        result,
        reason: reason.into(),
        scope: "A1_ENVELOPE_INTEGRITY",
        identity: "UNKNOWN",
        authority: "UNKNOWN",
        current_validity: "UNKNOWN",
        signatures: "UNKNOWN",
        archive_inclusion: "UNKNOWN",
    }
}

// A custom JSON visitor rejects duplicate keys before serde can discard them.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("PALACO-JSON-A1 value")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                if v.unsigned_abs() > MAX_INTEGER {
                    return Err(E::custom("integer out of range"));
                }
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                if v > MAX_INTEGER {
                    return Err(E::custom("integer out of range"));
                }
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Strict, E> {
                Err(E::custom("floats forbidden"))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if !valid_key(&key) || values.insert(key, value).is_some() {
                        return Err(de::Error::custom("invalid or duplicate object key"));
                    }
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key.as_bytes()[0].is_ascii_lowercase()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
}
fn digest_format(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse bounded UTF-8 JSON with duplicate-key and numeric-profile checks.
pub fn parse_strict(input: &[u8]) -> Result<Value, String> {
    if input.len() > MAX_BUNDLE_BYTES {
        return Err("bundle too large".into());
    }
    let value = serde_json::from_slice::<Strict>(input)
        .map(|v| v.0)
        .map_err(|e| e.to_string())?;
    canonical_bytes(&value)?;
    Ok(value)
}

/// Canonical PALACO-JSON-A1 bytes: sorted ASCII keys and safe integers only.
/// Strings preserve Unicode scalar values; no Unicode normalization is applied.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    fn write(value: &Value, out: &mut String, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err("canonical nesting exceeds 64".into());
        }
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(v) => {
                let n = v.as_i64().ok_or("integer required")?;
                if n.unsigned_abs() > MAX_INTEGER {
                    return Err("integer out of range".into());
                }
                out.push_str(&n.to_string());
            }
            Value::String(v) => out.push_str(&serde_json::to_string(v).map_err(|e| e.to_string())?),
            Value::Array(values) => {
                out.push('[');
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(v, out, depth + 1)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                let sorted: BTreeMap<_, _> = values.iter().collect();
                for (i, (key, v)) in sorted.into_iter().enumerate() {
                    if !valid_key(key) {
                        return Err("invalid key".into());
                    }
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).map_err(|e| e.to_string())?);
                    out.push(':');
                    write(v, out, depth + 1)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(value, &mut out, 0)?;
    Ok(out.into_bytes())
}

/// Hash a canonical value using a supported, domain-separated profile.
pub fn digest(profile: &str, domain: &str, value: &Value) -> Result<String, String> {
    if profile != HASH_PROFILE || !["MANIFEST", "PAYLOAD", "RECORD"].contains(&domain) {
        return Err("unsupported profile or domain".into());
    }
    let mut hash = Sha256::new();
    hash.update(format!("PALACO:CITADEL:{domain}:A1\0").as_bytes());
    hash.update(canonical_bytes(value)?);
    Ok(format!("{:x}", hash.finalize()))
}

fn without(value: &Value, key: &str) -> Value {
    let mut copy = value.clone();
    if let Some(map) = copy.as_object_mut() {
        map.remove(key);
    }
    copy
}

/// Verify a complete genesis-to-head bundle against separately supplied anchors.
/// A `Valid` receipt covers envelope integrity only; it never activates a Citadel.
pub fn verify(input: &[u8], expected_manifest: &str, expected_head: &str) -> VerificationReceipt {
    use VerificationResult::*;
    let value = match parse_strict(input) {
        Ok(v) => v,
        Err(_) => return receipt(Invalid, "MALFORMED_JSON_PROFILE"),
    };
    let root = match value.as_object() {
        Some(v) => v,
        None => return receipt(Invalid, "BUNDLE_OBJECT_REQUIRED"),
    };
    if root.len() != 2 || !root.contains_key("manifest") || !root.contains_key("records") {
        return receipt(Invalid, "BUNDLE_FIELDS");
    }
    let manifest: CitadelManifest = match serde_json::from_value(root["manifest"].clone()) {
        Ok(v) => v,
        Err(_) => return receipt(Invalid, "MANIFEST_SCHEMA"),
    };
    if manifest.schema_version != "0.1"
        || manifest.canonical_encoding != ENCODING
        || manifest.cryptographic_profile != HASH_PROFILE
        || manifest.lifecycle != "DRAFT"
    {
        return receipt(Unknown, "UNSUPPORTED_MANIFEST_PROFILE");
    }
    if !identifier(&manifest.citadel_id)
        || !identifier(&manifest.world_id)
        || blank(&manifest.purpose)
        || blank(&manifest.edition)
        || manifest.presentation.is_empty()
        || manifest.presentation.iter().any(|p| blank(p))
        || !digest_format(&manifest.manifest_digest)
    {
        return receipt(Invalid, "MANIFEST_FIELDS");
    }
    if digest(
        HASH_PROFILE,
        "MANIFEST",
        &without(&root["manifest"], "manifest_digest"),
    )
    .ok()
    .as_deref()
        != Some(&manifest.manifest_digest)
    {
        return receipt(Invalid, "MANIFEST_DIGEST");
    }
    if expected_manifest.is_empty() || expected_head.is_empty() {
        return receipt(Incomplete, "EXTERNAL_ANCHORS_REQUIRED");
    }
    if !digest_format(expected_manifest) || !digest_format(expected_head) {
        return receipt(Invalid, "ANCHOR_FORMAT");
    }
    if expected_manifest != manifest.manifest_digest {
        return receipt(Conflict, "MANIFEST_ANCHOR_CONFLICT");
    }
    let records = match root["records"].as_array() {
        Some(v) => v,
        None => return receipt(Invalid, "RECORDS_ARRAY_REQUIRED"),
    };
    if records.is_empty() {
        return receipt(Unknown, "NO_RECORDS");
    }
    let mut ids = BTreeMap::new();
    let mut sequences = BTreeSet::new();
    let mut previous: Option<String> = None;
    let mut signed = false;
    for (i, value) in records.iter().enumerate() {
        if value
            .as_object()
            .map(|m| {
                m.len() != RECORD_KEYS.len() || RECORD_KEYS.iter().any(|k| !m.contains_key(*k))
            })
            .unwrap_or(true)
        {
            return receipt(Invalid, "ENVELOPE_FIELDS");
        }
        let r: CanonicalRecordEnvelope = match serde_json::from_value(value.clone()) {
            Ok(v) => v,
            Err(_) => return receipt(Invalid, "ENVELOPE_SCHEMA"),
        };
        if r.schema_version != "0.1" {
            return receipt(Unknown, "UNSUPPORTED_RECORD_VERSION");
        }
        if !identifier(&r.record_id)
            || !identifier(&r.actor_ref)
            || !r.payload.is_object()
            || blank(&r.created_at_display)
            || !digest_format(&r.record_digest)
            || !digest_format(&r.payload_digest)
            || r.previous_digest
                .as_ref()
                .is_some_and(|s| !digest_format(s))
        {
            return receipt(Invalid, "ENVELOPE_VALUES");
        }
        if ![
            "QuestionRecord",
            "EvidenceObject",
            "EpistemicAssessment",
            "DecisionThreshold",
            "DecisionRecord",
            "AuthorizationRecord",
            "ConsequenceRecord",
            "ReassessmentRecord",
            "RevocationEvent",
            "ProofLifecycleEvent",
        ]
        .contains(&r.record_type.as_str())
            || ![
                "UNKNOWN",
                "SUPPORTED",
                "CONTESTED",
                "INSUFFICIENT",
                "REFUTED",
            ]
            .contains(&r.epistemic_state.as_str())
        {
            return receipt(Invalid, "ENVELOPE_ENUM");
        }
        if r.citadel_id != manifest.citadel_id
            || r.world_id != manifest.world_id
            || r.manifest_digest != manifest.manifest_digest
        {
            return receipt(Conflict, "RESOURCE_CONTEXT_CONFLICT");
        }
        if ids.contains_key(&r.record_id) || !sequences.insert(r.sequence) {
            return receipt(Conflict, "DUPLICATE_ID_OR_SEQUENCE");
        }
        if r.sequence > i as u64 + 1 {
            return receipt(Incomplete, "SEQUENCE_GAP");
        }
        if r.sequence != i as u64 + 1 || r.previous_digest != previous {
            return receipt(Invalid, "CHAIN_ORDER");
        }
        if digest(HASH_PROFILE, "PAYLOAD", &r.payload).ok().as_deref() != Some(&r.payload_digest)
            || digest(HASH_PROFILE, "RECORD", &without(value, "record_digest"))
                .ok()
                .as_deref()
                != Some(&r.record_digest)
        {
            return receipt(Invalid, "RECORD_DIGEST");
        }
        let mut refs = BTreeSet::new();
        for reference in r
            .provenance_refs
            .iter()
            .chain(r.evidence_refs.iter())
            .chain(r.authorization_ref.iter())
            .chain(r.trusted_time_evidence.iter())
        {
            if !identifier(reference) {
                return receipt(Invalid, "REFERENCE_FORMAT");
            }
            if reference == &r.record_id {
                return receipt(Invalid, "SELF_REFERENCE");
            }
            if !ids.contains_key(reference) {
                return receipt(Incomplete, "DEPENDENCY_MISSING_OR_NOT_PRIOR");
            }
            refs.insert(reference);
        }
        if r.evidence_refs
            .iter()
            .any(|id| ids.get(id).map(String::as_str) != Some("EvidenceObject"))
            || r.authorization_ref
                .as_ref()
                .is_some_and(|id| ids.get(id).map(String::as_str) != Some("AuthorizationRecord"))
        {
            return receipt(Invalid, "REFERENCE_TYPE");
        }
        for list in [&r.provenance_refs, &r.evidence_refs] {
            if list.iter().collect::<BTreeSet<_>>().len() != list.len() {
                return receipt(Invalid, "DUPLICATE_REFERENCE");
            }
        }
        signed |= r.signature.is_some();
        previous = Some(r.record_digest);
        ids.insert(r.record_id, r.record_type);
    }
    if previous.as_deref() != Some(expected_head) {
        return receipt(Incomplete, "ANCHORED_HEAD_NOT_PRESENT");
    }
    if signed {
        return receipt(Unknown, "SIGNATURE_PROFILE_NOT_IMPLEMENTED");
    }
    receipt(Valid, "A1_INTEGRITY_MATCHES_EXTERNAL_ANCHORS")
}

// Frozen A1 code points; do not inherit runtime Unicode whitespace tables.
fn blank(value: &str) -> bool {
    value.chars().all(|c| {
        matches!(c as u32,
        0..=0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a |
        0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
    })
}
