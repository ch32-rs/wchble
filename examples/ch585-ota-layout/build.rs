fn main() {
    // Put this crate's `memory.x` ahead of the one metapac emits, then let
    // qingke-rt's `link.x` INCLUDE it.
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
}
