fn main() {
    // `memory.x` comes from ch5xx-metapac (`ORIGIN=0x20003800`, 18K).
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
}
