//! Offline interoperability probe; this does not verify or authorize records.
use palaco_citadel_contracts::{canonical_bytes, digest, parse_strict, MAX_BUNDLE_BYTES};
use std::{env, fs::File, io::Read, process::ExitCode};

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: citadel-a1-canonical JSON_FILE".into());
    }
    let mut input = Vec::new();
    File::open(&args[0])
        .and_then(|f| f.take(MAX_BUNDLE_BYTES as u64 + 1).read_to_end(&mut input))
        .map_err(|e| e.to_string())?;
    let value = parse_strict(&input)?;
    let bytes = canonical_bytes(&value)?;
    let result = serde_json::json!({
        "canonical_bytes": bytes,
        "manifest_digest": digest("SHA256-DOMAIN-A1", "MANIFEST", &value)?,
        "payload_digest": digest("SHA256-DOMAIN-A1", "PAYLOAD", &value)?,
        "record_digest": digest("SHA256-DOMAIN-A1", "RECORD", &value)?
    });
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}
