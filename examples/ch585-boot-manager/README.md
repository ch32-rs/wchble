# CH585 OTA boot manager

X6b boot manager: 16 KiB at `0x0` owns the reset vector, validates the two
app slots, persists rollback state in DataFlash, and jumps to the selected
slot. Chip-agnostic image/metadata codecs and the state machine live in
`wchble::ota`; this crate is the CH585 glue.

## Memory map

| Region | Range | Use |
| --- | --- | --- |
| BOOT | `0x0000_0000` + 16 KiB | this image (gate: ≤ 0x3C00 `readelf`) |
| Slot A | `0x0000_4000` + 216 KiB | app header at base, entry at +0x20 |
| Slot B | `0x0003_A000` + 216 KiB | same |
| Metadata | DataFlash `0x70000` / `0x70100` | `DualCopyStore` pages |

It **never writes CodeFlash** and never erases a slot sector: the header is
host-stamped, and runtime trust is the metadata good mark. The body is not
re-read at boot (CH585 engine long reads are unreliable); the image CRC stays
in the header for the X6c write path. The only writes are the two metadata
pages.

## Boot flow

1. `hal::init(HSE_PLL_78MHZ)` (flash engine clock), SysTick µs clock
2. Read + validate both slot headers (magic/format/length/header CRC)
3. Load metadata (`DualCopyStore`): blank flash is a fresh device; pages that
   were written but cannot be decoded are untrusted
4. `ota::select()`; untrusted metadata uses `ota::select_recovery()`, which
   picks the factory slot instead of the highest sequence, so lost failure
   marks cannot revive a failed slot
5. Persist `attempts_done` **before** jumping, fill `BOOT_STATS`, then
   `csrci mstatus,8; fence.i; jr slot_base+0x20`

`BOOT_STATS` (`#[no_mangle] static mut`, magic `0x544F_4F42`): slot states, sequences,
selected slot, attempts, action, metadata load/save status, elapsed µs,
rollback flag. Actions: `0` boot, `1` no valid slot, `2` all failed,
`3` metadata write failed. `meta_load`: `0` blank, `1` trusted record,
`2` undecodable payload, `3` untrusted pages, `4` read error. Park states
feed the watchdog and never reset.

## Build and check

```bash
cd examples/ch585-boot-manager
cargo build --release
python3 ../../tools/ota_image.py verify-elf --role boot \
  --elf target/riscv32imc-unknown-none-elf/release/ch585-boot-manager
```

`verify-elf` asserts entry `0x0`, flash extent ≤ `0x3C00`, a `.highcode`
segment (RAM VMA, flash LMA), and `BOOT_STATS` inside `0x2000_0000..0x2000_0080`.
Flash it with `probe-rs download`; use the same probe settings as the other
CH585 examples. Slot images are built and stamped from
`examples/ch585-ota-layout`.
