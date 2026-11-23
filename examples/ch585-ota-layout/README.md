# CH585 OTA slot carrier

App image linked into slot A or slot B of the X6b boot manager
(`examples/ch585-boot-manager`). One source, two layouts:

| Feature | Slot | App origin | Header |
| --- | --- | --- | --- |
| `slot-a` (default) | A | `0x0000_4020` | `0x0000_4000` |
| `slot-b` | B | `0x0003_A020` | `0x0003_A000` |

The 32 B header at the slot base is written by `tools/ota_image.py stamp`, not
by this crate. `qingke-rt` needs `.init` (`j handle_reset`) at
`ORIGIN(FLASH)`, hence the +0x20 app origin.

## What it does

1. `hal::init(rcc)` (HSE 60 MHz) and SysTick µs clock
2. Radio init (`new_radio_with_dma` → `init`)
3. Load the boot metadata (`DualCopyStore` over DataFlash), apply
   `ota::on_good()`, save only when the record changes
4. Record `OTA_SLOT` for a probe read, advertise
   `ADV_NONCONN_IND` as **`wch585-ota-a`** or **`wch585-ota-b`**

`OTA_SLOT` (16 words, v2): magic `OTA2`, `_stext`, slot index, built `OTA_SEQUENCE`,
previous `candidate_slot` / `attempts_done` / `good_seq` / `flags`,
`mark_good_ok`, `mark_good_us`, `load_ok`, adv loop count, slot base.

## Build

`--target` is explicit: this crate has no `.cargo/config.toml`, and the host
build would fail on RISC-V asm. Each slot goes to its own target dir so the
two releases do not overwrite each other.

```bash
cd examples/ch585-ota-layout
OTA_SEQUENCE=2 cargo build --release --features slot-a \
  --target riscv32imc-unknown-none-elf --target-dir target/slot-a
OTA_SEQUENCE=3 cargo build --release --no-default-features --features slot-b \
  --target riscv32imc-unknown-none-elf --target-dir target/slot-b
```

`OTA_SEQUENCE` (default 1, 0 rejected) is compiled in as `OTA_IMAGE_SEQUENCE`;
`stamp` refuses a mismatch between it and `--sequence`.

## Features

| Feature | Effect |
| --- | --- |
| `slot-a` / `slot-b` | Exactly one must be on; picks the `memory.x` |
| `no-good` | Skip the good-mark save, so the boot manager rolls the slot back |
| `ota-fault-mark-good` | Truncated good-mark write (`save_with_fault`), then halt |
| `wipe-meta` | Erase both metadata pages, then park (the runner resets) |
| `poison-meta` | Write non-blank garbage over both metadata pages, then park |

`wipe-meta` is the round reset: the probe cannot write DataFlash on a running
target, so metadata test states are reached through device code.

The carrier marks the slot good right after radio init, before advertising.
A production BLE app should mark good only once its stack and event loop run.

## Stamp and flash

```bash
python3 tools/ota_image.py verify-elf --role slot-a \
  --elf examples/ch585-ota-layout/target/slot-a/riscv32imc-unknown-none-elf/release/ch585-ota-layout
python3 tools/ota_image.py stamp --elf <same ELF> --slot a --sequence 2 --out-dir out
probe-rs download --probe 1a86:8010:<SERIAL> --chip CH585 --protocol jtag \
  --verify out/slot-a.hex
```

Flash the stamped HEX, not the ELF: its bytes are exactly the CRC input.
`probe-rs` erases only the target sectors; use `--no-chip-erase` semantics
(the runner passes `do_chip_erase=false`) so a download to B cannot disturb A.

Non-secure builds only: a secure `ch585-trouble-gatt` image exceeds one slot
(see `local-docs/ch585-ota-spec.md`).
