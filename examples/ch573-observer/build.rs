use std::fs;
use std::path::PathBuf;

fn main() {
    // `memory.x` comes from ch5xx-metapac (`ORIGIN=0x20003800`, 18K).
    println!("cargo:rustc-link-arg-bins=-Tlink.x");

    // CH573 DMA address registers keep only the low 14 bits, so the engine
    // reaches `0x2000_4000 | (reg & 0x3FFF)` = the last 16 KiB of SRAM.
    // Keep the buffers well inside that window; the stack grows below them.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let script = out.join("dma_buffer.x");
    fs::write(
        &script,
        r#"SECTIONS {
    .dma_buffer ORIGIN(RAM) + LENGTH(RAM) - 0x3400 (NOLOAD) :
        { *(.dma_buffer .dma_buffer.*) } >RAM
}
ASSERT(SIZEOF(.dma_buffer) == 0 || ADDR(.dma_buffer) >= ORIGIN(RAM) + LENGTH(RAM) - 0x4000,
       "dma_buffer below CH573 DMA window (0x2000_4000)")
ASSERT(SIZEOF(.dma_buffer) <= 0x400, "dma_buffer exceeds reserved 0x400")
_stack_start = SIZEOF(.dma_buffer) ? ADDR(.dma_buffer) : ORIGIN(RAM) + LENGTH(RAM);
"#,
    )
    .unwrap();
    println!("cargo:rustc-link-arg-bins=-T{}", script.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CH573_OBS_RUN_S");
}
