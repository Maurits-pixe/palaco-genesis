//! Offline verifier: no database, network, secrets or UI are required.
use palaco_citadel_contracts::{verify, VerificationResult, MAX_BUNDLE_BYTES};
use std::{env, fs::File, io::Read, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: citadel-a1 BUNDLE EXPECTED_MANIFEST_DIGEST EXPECTED_HEAD_DIGEST");
        return ExitCode::from(64);
    }
    let mut input = Vec::new();
    let read = File::open(&args[0])
        .and_then(|f| f.take(MAX_BUNDLE_BYTES as u64 + 1).read_to_end(&mut input));
    if read.is_err() {
        eprintln!("cannot read bundle");
        return ExitCode::from(66);
    }
    let result = verify(&input, &args[1], &args[2]);
    match serde_json::to_string(&result) {
        Ok(s) => println!("{s}"),
        Err(_) => return ExitCode::from(70),
    }
    if result.result == VerificationResult::Valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
