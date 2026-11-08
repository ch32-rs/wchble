# CH32V208 NimBLE live baseline (for on-air A/B)

Date: 2026-11-08

`ch32v208-nimble` (`/Users/mono/Repos/ch32v208-nimble`) is the known-good
NimBLE controller+host firmware for this board. Use it as the **live A/B
reference** for macOS visibility: same board, same Mac, same scan tool. Do not
adjust our RF/PDU code from guesses before the baseline itself is stable.

## Build

```sh
export WCH_TOOLCHAIN_DIR="/Applications/MounRiver Studio 2.app/Contents/Resources/app/resources/darwin/components/WCH/Toolchain/RISC-V Embedded GCC15"
git clone --depth 1 https://github.com/apache/mynewt-nimble /Users/mono/Repos/nimble
cd /Users/mono/Repos/ch32v208-nimble
scripts/build.sh
```

Current upstream NimBLE needs one extra default in
`config/syscfg/syscfg_overrides.h` (host `ble_sm.c` references it):

```c
#define MYNEWT_VAL_BLE_SM_MIN_KEY_SIZE (7)
```

Flash only the selected probe (three WCH-LinkEs are attached):

```sh
probe-rs download --chip CH32V208WBU6 --probe 1a86:8010:2FC48F06B4A8 \
  build/ch32v208_nimble.elf
probe-rs reset --chip CH32V208WBU6 --probe 1a86:8010:2FC48F06B4A8
```

Scan with `tools/macos-ble/ble.sh scan --name CH32V208-NIMBLE --timeout 20`.
Note: macOS caches the `kCBAdvDataLocalName` per identity; also match the
2-byte manufacturer bytes `5743` (`kCBAdvDataManufacturerData`).

## Observed stall (2026-11-08)

Reading the PHY counters without RTT (a `probe-rs read` halts the core, so take
one snapshot after the measurement window and reset afterwards):

```sh
probe-rs read --chip CH32V208WBU6 --probe 1a86:8010:2FC48F06B4A8 \
  b32 0x20002aa0 16      # g_ble_phy_stats
```

After `reset` + 5 s: `phy_isrs=56 tx_good=27 tx_started=27 rx_starts=2
rx_aborts=1 rx_valid=1`. After reset + 15 s scan: `phy_isrs=44 tx_good=20
rx_started=20 rx_starts=4 rx_aborts=3 rx_valid=1`. Advertising interval is
100 ms × 3 channels, so a running advertiser should show ~30 TX/s; the counters
stop after roughly 0.7–0.9 s. The Mac scan therefore sees nothing.

A speculative fix that closes the RX window with `ble_ll_wfr_timer_exp(NULL)`
when `ble_ll_rx_start()` rejects a stray PDU was tried and **did not** resolve
the stall (TX still stopped after ~7 events). It was reverted; the reference
checkout only keeps the `syscfg_overrides.h` addition needed to build against
current upstream NimBLE. This stall is not blocking `wchble` anymore: our
firmware is now visible on air, and the root cause there was a different one
(sticky `TX_DONE`, see `docs/progress.md`).

## Tried fix (did not resolve the stall)

`drivers/wch_ble/ble_phy_wch.c`, `phy_rx_done_isr()`:

1. `hal_timer_stop(&s_phy_wfr_timer)` is called as soon as a PDU completes.
2. `ble_ll_rx_start()` is called late (completion, not address match).
3. When it returns `< 0` (a stray packet caught in the post-TX advertising
   window), the handler calls `ble_phy_disable()` and returns. Nothing tells
   the LL the window ended, and the software WFR timer was already stopped.

Closing that window with `ble_ll_wfr_timer_exp(NULL)` was tried (and reverted):
`rx_timeouts` started advancing, but TX still stopped after ~7 events.
`phy_rx_timeout_isr()` returns early once `phy_state != RX`, so simply
re-arming the software timer is not equivalent either. The real cause remains
open; do not treat a fresh `ch32v208-nimble` build as a long-running reference
until it is understood.

## Verification used for `wchble`

- Our firmware's own counters (`TX_BURSTS`/`TX_OK`/`TX_TRY` in RAM) show
  continuous 3-channel TX at the 100 ms interval.
- `tools/scan_wchble.swift` in `examples/ch32v208-trouble-adv` reports
  `FOUND wchble` via macOS CoreBluetooth.
- If the baseline is visible but `wchble` is not, compare our `tx_basic`
  sequence/registers against this driver. Two differences were found while
  debugging: TX buffer alignment (fixed) and, decisively, the sticky
  `TX_DONE` W1C bit (see `docs/progress.md`).
