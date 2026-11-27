# wchble

Embassy-style Bluetooth Low Energy layer for WCH MCUs, consumed by
[`ch32-hal`](https://github.com/ch32-rs/ch32-hal) and
[`ch5xx-hal`](https://github.com/ch32-rs/ch5xx-hal) — not a standalone firmware
crate.

HALs own clocks, NVIC, Embassy executor, and board bring-up. This crate owns
the radio → soft PHY → link layer → soft HCI path that Trouble Host drives,
mirroring how Embassy splits [`bt-hci`](https://github.com/embassy-rs/bt-hci) +
[`trouble`](https://github.com/embassy-rs/trouble) from chip HALs.

```text
Trouble Host          (in HAL examples / apps)
    ↕  bt-hci (in-process soft HCI)
wchble::hci
    ↕
wchble::ll            # Rust link layer
    ↕
wchble::phy           # soft IFS / WFR
    ↕
wchble::rf            # pure Rust MMIO radio HAL
    ↕
ch32-hal / ch5xx-hal  # RCC BLE clock, HSE trim, IRQ install, time
```

RF backends (cfg-per-family under `src/rf/family/`):

| Feature | Status |
| --- | --- |
| `ch32v208` | DevInit/cal + channel/shut/tx_basic/rx_basic/ISR (open `wch_rf`); HAL smoke next |
| `ch572` | CH5xx map + unique new-table constants (`0x64` / `0x16000F`); MMIO TBD |
| `ch573` | DevInit/cal + DMA-block TX/RX; **DMA window `@0x20004000..0x20008000`**; **ADV TX verified on air** (`examples/ch573-rf-smoke`); **ADV RX verified byte-exact** against a known transmitter + RSSI (`examples/ch573-rx-smoke`); CRC status and real LLE/BB IRQ still open |
| `ch583` | Bases + closed-disasm “old tables” (≈V208); MMIO apply TBD |
| `ch585` | DevInit/cal + channel/shut/tx_basic/rx_basic (carved CH585EVT lib) — **verified on air** (`examples/ch585-rf-smoke`) |
| `ch592` | DevInit/cal + channel/shut/tx_basic/rx_basic — **verified on air** (`examples/ch592-rf-smoke`) |
| `ch595` | Near-CH585 tables without `nCO2522` (`0x84` highs); MMIO TBD |

Uncertain fields are tagged `UNCERTAIN` / `Certainty::*` for silicon debug.

> **RF/LL/HCI bring-up requires independent on-air verification.** A stale
> sticky W1C `TX_DONE` can make TX report success without transmitting; clear
> completion status before a new TX. Respect the radio's DMA alignment
> requirements and seed a valid AdvA. Verify radiation with a second receiver,
> not merely a TX completion or timeout.

This repository used to wrap closed WCH `.a` BLE libraries via bindgen. That
path is gone; the open register-level work continues from the CH32V208 NimBLE
RF bring-up (`wch_rf`).

## Workspace

| Path | Role |
| --- | --- |
| `src/rf` | L0 radio HAL |
| `src/phy` | L1 schedule / IFS / WFR |
| `src/ll` | L2 link layer |
| `src/hci` | L3 soft HCI (`bt-hci` Controller) |
| `examples/` | Flashable RF smoke + Trouble ADV examples |

On-target bring-up examples live in this repo while the HAL integration is in
flight; production firmware still belongs in the HAL repos.

## Features

```bash
# Radio / family only (HAL RF bring-up)
cargo check --features ch32v208

# Soft HCI + LL surface for Trouble
cargo check --features ch32v208,controller,phy
```

Enable **at most one** chip feature (`ch32v208`, `ch572`, `ch573`, `ch583`,
`ch585`, `ch592`, `ch595`).

## HAL integration sketch

```rust,ignore
// inside ch32-hal / application after BLE AHB clock + HSE trim (IRQs still off):
use wchble::hci::{self, SoftRunner};
use wchble::rf::family::ch32v208::Ch32v208Radio;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::Radio;

static RX: StaticCell<[u8; RX_DMA_MIN]> = StaticCell::new();
let mut radio = Ch32v208Radio::new(RX.init([0; RX_DMA_MIN]))?;
radio.init(&hal_clock)?; // LLE → RFEND → BB → cal; HAL enables NVIC after

let controller = hci::new(); // ExternalController<HciTransport, 4>
let mut soft = SoftRunner::new();
// soft.set_bd_addr([...]);

// join Trouble's runner with SoftRunner::run — SoftRunner must reply
// Command Complete or Host exec hangs waiting on the in-process channel.
// let stack = trouble_host::new(controller, &mut resources);
```

For on-target RF smoke before Trouble, see
[`examples/ch32v208-rf-smoke`](examples/ch32v208-rf-smoke) and the CH585 and
CH592 RF smoke examples. Verify transmitted packets with a second receiver.

## Status

**CH585 direct-radio bring-up** (2026-11-09):
[`ch585-scannable`](examples/ch585-scannable) has verified scan responses;
[`ch585-peripheral`](examples/ch585-peripheral) adds an unencrypted LE 1M,
CSA #1 connection prototype. macOS connect/hold/disconnect has passed ten
successive 10-second cycles with firmware data RX/TX evidence and a clean
360-second finite run. A separate 120-second client hold completed, but joint
firmware acceptance failed on a duration discrepancy and a later extra connection
with supervision timeout; it is not reported as passing. This example bypasses
the scaffold HCI runner: it is not yet a Trouble/GATT peripheral, and air IFS is
unmeasured.

**CH585 P4 real Host/GATT integration** (2026-11-10):
[`ch585-trouble-gatt`](examples/ch585-trouble-gatt) connects the event-level radio
pump to a bounded single-connection soft HCI/ACL bridge and real Trouble Host.
The native real-Host fixture passes discovery, read/write, notification, credit
recycling and reconnect tests. With nominal HSE/PLL timing and a corrected RX
completion deadline, two separate five-cycle macOS runs passed service/
characteristic discovery, reads, writes, verified sequence notifications,
unsubscribe and normal disconnect/reconnect. Each run completed 25 reads,
65 writes and 50 notifications, with clean finite RF finish and smoke recovery. Earlier failed attempts are retained. The original
single-cycle capture had a CRC-bad CONNECT and required forced shutdown. A separate
new capture verified all three connections, bidirectional data and notifications,
with clean SIGINT shutdown in that run. Packet evidence then exposed a receive
start/completion deadline mix-up; its correction reduced missed events from
168/339 to 1/172 and restored 1:1 data exchange in the captured links. Whole-run
sniffer following and orderly shutdown remain intermittent, not guaranteed.

The first manual P4 phone check succeeded on 2026-11-10: the user reports all
five requested steps (read, Write Request/readback, notifications, disabled-
notification write/read, disconnect/reconnect persistence) completed on Android,
and a later iOS attempt also succeeded, in one directly flashed 360-second window.
Firmware recorded four accepted connections and disconnects, six reads, five
writes, five queued notifications, `0xAAAAAAAA` final value, no Host/bridge/RF
stop/TX/RX/supervision error, and a clean 360.000021 s finish; smoke recovery and
discovery passed. Both platforms' counters share that window, so platform
attribution relies on the user's separate UI observations. This is one manual
session per platform, not the planned three isolated acceptance rounds or
wireless capture evidence; sustained reliability remains unverified.

The preflight defect is fixed in `tools/ch585-preflight`: one retained probe
session halts, stops the engine, requires two zero acknowledgements, verifies
the download and starts the image. Two clean three-cycle macOS acceptance runs
then passed with exactly three connections/disconnects, fifteen reads, thirty-
nine writes, thirty notifications and no missed events, retries, supervision or
bridge errors; smoke recovery passed both times. Earlier attempts are retained:
one had an extra connection while a phone was still present, and one hit a
transient download failure. Sustained reliability, supervision-timeout recovery,
queue-pressure stress and calibrated air timing remain unverified. Open gaps are
tracked in [`BACKLOG.md`](BACKLOG.md). See the example for the finite runner and
safety/recovery policy.

**CH585 P5 service expansion** (2026-11-10):
[`ch585-trouble-gatt`](examples/ch585-trouble-gatt) now also exposes the
standard Device Information Service (manufacturer/model/revision) and a Nordic
UART-style write/notify pipe. The native real-Host fixture covers DIS discovery
and reads plus a UART write/echo notification; a three-cycle macOS run read all
three information fields and echoed three distinct strings without RF, Host or
bridge errors, then restored smoke. ATT MTU remains 23, so long-data/MTU
negotiation and UART flow stress are not yet validated. See
[`BACKLOG.md`](BACKLOG.md).

**CH585 OTA slot-A layout** (2026-11-15):
[`ch585-ota-layout`](examples/ch585-ota-layout) links the app at `0x4000`
(slot A, 216 KiB) and leaves a four-byte jump at the reset vector `0x0`, so one
non-secure release ELF both resets into the slot and runs from it. After reset
the image advertised `wch585-ota` to a macOS CoreBluetooth scan (69
observations), and the board was restored to the smoke image. The stub stands
in for the real boot manager: an update still rewrites the whole image. Secure
builds of the trouble-host examples exceed one slot.

**CH585 X3 dual-link PP/CP subsets** (2026-11-18):
[`examples/ch585-trouble-gatt`](examples/ch585-trouble-gatt) can now drive two
links from one scheduler table. `--features pp` holds two peripheral links and
keeps advertising while a slot is free; `--features cp` holds one outbound
central link to an Android GATT server and one inbound peripheral link from a
macOS client in the same round. Both pass finite macOS/Android rounds (host two
connections/disconnects, clean rate and bridge error counters, smoke restored).
Plaintext PP/CP subsets landed first; `pp+secure` closed in PR #25 and central
encrypted outbound / HOGP host paths landed in PR #35. Still open: reverse CP
connect order and Create Connection Cancel on hardware (Phase 1 C4), the
Phase 1 A2 total ACL-credit streaming claim, and the rest of the X3.3
acceptance scope (see `BACKLOG.md`). Phase 1 central HOGP **code is merged**;
the milestone stays open until every Phase 1 gate PASSes.

**CH585 X2a extended advertising (advertiser subset)** (2026-11-20):
[`examples/ch585-trouble-gatt`](examples/ch585-trouble-gatt) with
`--features x2-ext-adv[-2m]` runs a real Trouble `advertise_ext` beacon:
ADV_EXT_IND on 37/38/39 pointing at a data-channel AUX_ADV_IND 600 µs out
(same scheduled-TX path, so the air gap equals the AuxPtr), rotating aux
channel, DID rotation and the LE extended advertising feature bit. Both N=1
rounds passed on hardware (1M and 2M secondary): `adv_tx==aux_tx==rounds`
(453/456), `aux_late==0`, `events` matching the 160 ms interval, aux air time
exactly 80+8n / 44+4n µs, and the Android non-legacy scanner received the full
128-byte CRC-32 marker byte-for-byte (`secondary_phy:2` on the 2M image);
nRF Connect corroborates the 1M round. The first hardware round exposed a real
defect: the `Advertiser` returned by `advertise_ext` was dropped, and its Drop
guard disabled the set right after enabling (a doubled `0x2039` in the
controller log); fixed by holding the Advertiser with a mutation-checked
fixture gate. Verified subset only: non-connectable, non-scannable, one set,
128-byte data; coexistence against a live link, periodic advertising and
PAwR remain open (see `BACKLOG.md`).

**CH585 X1b LE 2M PHY subset** (2026-11-19):
[`examples/ch585-trouble-gatt`](examples/ch585-trouble-gatt) with `--features
secure,x1b-2m` advertises the LE 2M feature bit and moves one peripheral link
through `LL_PHY_REQ`/`RSP`/`UPDATE_IND`. Both initiators passed N=1 on hardware
(Host `LE Set PHY` and an Android `setPreferredPhy`): `LE Read PHY` 2/2, and
encrypted ATT MTU 124 reads/writes/notifications ran at 2M with no CRC or
supervision errors. Verified subset only: one peripheral link to a 2M-capable
central. The 1M-only peer fallback, Coded PHY and Central-side PHY remain
uncovered, and `pp`/`cp` builds keep both bits clear (see `BACKLOG.md`).

**Soft HCI Phase B verified on air** (2026-11-08): `hci::new()` is
`bt_hci::ExternalController` over bounded embassy channels; `SoftRunner`
answers Reset / ReadBdAddr / event masks / LE buffer size / legacy adv cmds.
[`examples/ch32v208-trouble-adv`](examples/ch32v208-trouble-adv) joins
SoftRunner with a Trouble Host and advertises ADV_IND on 37/38/39; macOS
CoreBluetooth sees `wchble` (`RSSI ≈ -54`) via
`examples/ch32v208-trouble-adv/tools/scan_wchble.swift`. Next: SCAN_RSP /
connections (Phase C).

## License

Apache-2.0. See `LICENSE-APACHE`.
