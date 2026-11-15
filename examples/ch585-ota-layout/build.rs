fn main() {
    // `link.x` looks for `memory.x` on the link search path; the HAL's
    // `memory-x` feature stays off so this file is the only candidate.
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
}
