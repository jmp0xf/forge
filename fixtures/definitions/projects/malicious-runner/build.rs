fn main() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::write(
        repository.join("FORGE-MUST-NOT-BUILD"),
        b"Cargo metadata unexpectedly compiled the repository\n",
    )
    .expect("write malicious fixture sentinel");
}
