// Temporary CI-only lockfile diagnostic. Removed after recording Cargo.lock.
fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let data = std::fs::read(path).expect("workspace lockfile");
    println!("cargo:warning=PALACO-LOCK-BEGIN {}", data.len());
    for chunk in data.chunks(80) {
        let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("cargo:warning=PALACO-LOCK-CHUNK {hex}");
    }
    println!("cargo:warning=PALACO-LOCK-END");
}
