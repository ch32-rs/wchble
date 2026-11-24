fn main() {
    // `memory.x` comes from ch5xx-metapac's `memory-x` feature; `link.x` and
    // the QingKe startup live in qingke-rt.
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
}
