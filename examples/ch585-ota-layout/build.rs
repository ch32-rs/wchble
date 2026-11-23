fn main() {
    let slot_a = std::env::var_os("CARGO_FEATURE_SLOT_A").is_some();
    let slot_b = std::env::var_os("CARGO_FEATURE_SLOT_B").is_some();
    assert!(
        slot_a ^ slot_b,
        "enable exactly one of the `slot-a` / `slot-b` features"
    );

    let (index, slot_base, template) = if slot_a {
        (0u8, 0x0000_4000u32, "memory-slot-a.x")
    } else {
        (1u8, 0x0003_A000u32, "memory-slot-b.x")
    };
    let sequence: u32 = match std::env::var("OTA_SEQUENCE") {
        Ok(value) => value.parse().expect("OTA_SEQUENCE must be a u32"),
        Err(_) => 1,
    };
    assert!(sequence != 0, "OTA_SEQUENCE 0 is reserved as invalid");

    // The slot script must be the only `memory.x` on the link search path.
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::copy(template, format!("{out}/memory.x")).unwrap();
    std::fs::write(
        format!("{out}/ota_config.rs"),
        format!(
            "pub const OTA_SLOT_INDEX: u8 = {index};\n\
             pub const OTA_SLOT_BASE: u32 = {slot_base:#010x};\n\
             pub const OTA_SEQUENCE: u32 = {sequence};\n"
        ),
    )
    .unwrap();

    println!("cargo:rustc-link-search={out}");
    println!("cargo:rustc-link-arg-bins=-Tram-mem.x");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-slot-a.x");
    println!("cargo:rerun-if-changed=memory-slot-b.x");
    println!("cargo:rerun-if-changed=ram-mem.x");
    println!("cargo:rerun-if-env-changed=OTA_SEQUENCE");
}
