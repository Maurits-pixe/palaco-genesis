//! Frozen A1 interoperability and adversarial tests.
use palaco_citadel_contracts::{canonical_bytes, digest, parse_strict, verify, VerificationResult};
use serde_json::{json, Value};
const BUNDLE: &[u8] = include_bytes!("../../../verification/citadel-a1/bundle.json");
const EXPECTED: &[u8] = include_bytes!("../../../verification/citadel-a1/expected.json");
fn fixtures() -> Result<(Value, Value), String> {
    Ok((parse_strict(BUNDLE)?, parse_strict(EXPECTED)?))
}
fn anchors(e: &Value) -> Result<(&str, &str), String> {
    Ok((
        e["manifest_digest"].as_str().ok_or("manifest anchor")?,
        e["head_digest"].as_str().ok_or("head anchor")?,
    ))
}
fn check(v: &Value, e: &Value) -> Result<VerificationResult, String> {
    let (m, h) = anchors(e)?;
    Ok(verify(&serde_json::to_vec(v).map_err(|x| x.to_string())?, m, h).result)
}
#[test]
fn frozen_independent_vector() -> Result<(), String> {
    let (v, e) = fixtures()?;
    let (m, h) = anchors(&e)?;
    let r = verify(BUNDLE, m, h);
    assert_eq!(r.result, VerificationResult::Valid);
    assert_eq!(r.authority, "UNKNOWN");
    assert_eq!(r.current_validity, "UNKNOWN");
    assert_eq!(r.archive_inclusion, "UNKNOWN");
    for (i, record) in v["records"].as_array().ok_or("records")?.iter().enumerate() {
        assert_eq!(
            String::from_utf8(canonical_bytes(&record["payload"])?).map_err(|x| x.to_string())?,
            e["payload_canonical_utf8"][i]
        );
        assert_eq!(
            digest("SHA256-DOMAIN-A1", "PAYLOAD", &record["payload"])?,
            e["payload_digests"][i]
        );
    }
    Ok(())
}
#[test]
fn tampering_is_invalid() -> Result<(), String> {
    let (mut v, e) = fixtures()?;
    v["records"][1]["payload"]["sample_count"] = json!(4);
    assert_eq!(check(&v, &e)?, VerificationResult::Invalid);
    Ok(())
}
#[test]
fn truncated_export_is_not_valid() -> Result<(), String> {
    let (mut v, e) = fixtures()?;
    v["records"].as_array_mut().ok_or("records")?.pop();
    assert_eq!(check(&v, &e)?, VerificationResult::Incomplete);
    Ok(())
}
#[test]
fn absent_evidence_and_anchors_do_not_mean_valid() -> Result<(), String> {
    let (mut v, e) = fixtures()?;
    v["records"] = json!([]);
    assert_eq!(check(&v, &e)?, VerificationResult::Unknown);
    assert_eq!(
        verify(BUNDLE, "", "").result,
        VerificationResult::Incomplete
    );
    Ok(())
}
#[test]
fn duplicate_identity_conflicts() -> Result<(), String> {
    let (mut v, e) = fixtures()?;
    v["records"][1]["record_id"] = v["records"][0]["record_id"].clone();
    assert_eq!(check(&v, &e)?, VerificationResult::Conflict);
    Ok(())
}
#[test]
fn strict_json_and_canonical_boundaries() -> Result<(), String> {
    for raw in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1.0}"#,
        r#"{"a":-0}"#,
        r#"{"a":1e2}"#,
        r#"{"a":9007199254740992}"#,
        r#"{"A":1}"#,
        r#"{"a":"\ud800"}"#,
    ] {
        assert!(parse_strict(raw.as_bytes()).is_err(), "{raw}");
    }
    assert_eq!(
        canonical_bytes(&json!({"z":-1,"a":"Café\n水🏰\u{0000}"}))?,
        "{\"a\":\"Café\\n水🏰\\u0000\",\"z\":-1}".as_bytes()
    );
    assert_ne!(
        digest("SHA256-DOMAIN-A1", "PAYLOAD", &json!({}))?,
        digest("SHA256-DOMAIN-A1", "RECORD", &json!({}))?
    );
    assert!(digest("unknown", "PAYLOAD", &json!({})).is_err());
    Ok(())
}
