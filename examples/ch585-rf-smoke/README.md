# CH585 RF verify smoke

On-target verification for `wchble`'s CH585 (CH58x) RF path. On 2026-11-09,
TX/RX were exercised on air and macOS saw an earlier `wch585` ADV_IND. The
current non-connectable, non-scannable advertisement was seen by macOS and an
Android phone. This smoke example does not support scanning responses or connections.

## What it does

1. Bring up SYSCLK from the on-board 32 MHz HSE (`ch5xx-hal` `rcc`,
   `hse_nearest(60 MHz)` → the CH585 312 MHz PLL ladder picks the nearest)
2. Start a free-running SysTick µs clock (`InstantUs`)
3. `Ch585Radio::new` → `init` (`LLE_DevInit → RFEND_DevInit → TXCtune →
   BB_DevInit → calibration`)
4. Dump DevInit markers (`LLE+0x06/14/2c/3c/50/54/0c`, `RFEND+0x28/30/3c/44`,
   `BB+0x00/10/2c/34/38`)
5. Multi-channel ADV_NONCONN_IND TX on **37 / 38 / 39**
6. Two RX arming rounds on ch38 (arm-clear / timeout still proves the path)
7. Loop: ADV_NONCONN_IND on 37/38/39 + the vendor `RF_PHY` reference frame on ch39,
   with a periodic RX check on ch37

Console markers: `rf init ok`, `LLE …` / `RFEND …` / `BB …`,
`tx ch{37,38,39} ok`, `rx listen hit|arm-clear`, `adv loop`,
`rx loop hit len=N crc=true`.

## What the dump should show

The DevInit values this backend writes (CH585 carved `libCH58xBLE.a`):

| Marker | CH585 (expected) | CH592 for contrast |
| --- | --- | --- |
| `LLE 06` | `2` | `78` |
| `LLE 2c` / `3c` | `6c` | `6e` |
| `LLE 54` | `0` | `14` |
| `LLE 0c` (guard) | `1f000f` | `1f000f` |
| `BB 34` | `50` | `50` |
| `BB 38` | `3ff` | `ff` |
| `BB 3c` | `2020c` | `2020c` |
| `RFEND 28` | `480` (sticky high bits may differ) | `480` |

`tx chN ok` must be checked against a **second receiver** — a "TX ok" whose
window expired is not radiation. A macOS scan for the
local name `wch585` is the cheapest second receiver.

## Build / flash

```bash
cd examples/ch585-rf-smoke
cargo build --release
wlink -d 1a86:8010:<SERIAL> flash \
  target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke
# Power-cycle the target, or the BLE block stays idle:
wlink -d 1a86:8010:<SERIAL> set-power disable3v3
wlink -d 1a86:8010:<SERIAL> set-power enable3v3
```

Requires a sibling checkout of
[`ch5xx-hal`](https://github.com/ch32-rs/ch5xx-hal) at `../../../ch5xx-hal` and
`wlink` on `PATH`. Flash needs a WCH-LinkE with recent firmware (v3.6/v42 was
used here; v2.11/v31 times out on CH585 attach).

**The power cycle matters.** The LinkE's post-flash reset leaves the BLE block
idle — the same image that advertises fine after a `set-power` cycle was
invisible to macOS when only `wlink flash`'s reset was used.

If the board has no 32 MHz crystal, `hse_nearest` cannot produce the BLE
reference clock; use a CH585 board with the crystal fitted (all WCH EVT boards
have one).

## Reading the console

SDI print does not work on CH585 with the probe firmware at hand: the debug
data window at `0xE000_0340` reads `0xffff_ffff` from the host side even with
the probe in SDI-print mode. The example therefore mirrors its console into a
`#[no_mangle]` RAM buffer (`LOG`): a little-endian `u32` byte count followed by
UTF-8 text. Read it with probe-rs — `wlink dump` aliases CH585 RAM reads to
flash on this die:

```bash
nm target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke | grep ' LOG'
probe-rs read --chip CH585 b32 0x20000008 200
```

The same trick captures the trap CSRs in `TRAP` if the firmware faults.

`probe-rs read` attaches through the debug module and leaves the core halted
after it detaches, so the advertising loop stops until the target is
power-cycled again. Read the log first, then `set-power disable3v3/enable3v3`
before running the scanner (or scan before reading).

## Silicon results (2026-11-09)

1. `LLE+0x2C/+0x3C = 0x6C` (not CH592's `0x6E`) and `LLE+0x06 = 2`, exactly as
   carved from the CH585 lib.
2. TX completion was observed and macOS decoded the advertisement. The
   earlier elapsed-time log subtracted timestamps backwards; it was not an
   air-interface timing measurement.
3. `RFEND_DevInit` masks matter: passing the vendor's AND masks
   (`0xF8FFFFFF`, `0x81FFFFFF`) to `regs::rmw` as *clear* masks inverted the
   update and left VCO calibration constant across bands. With the corrected
   masks the calibration tables were populated and broadly matched the vendor
   `Peripheral.hex` capture, with differences in some words.
4. RX decodes nearby advertisers with `crc=true`; TX is confirmed by an
   external macOS scan seeing `wch585`.
