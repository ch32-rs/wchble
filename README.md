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

Enable **at most one** chip feature (`ch32v208`, `ch572`, `ch583`, `ch585`,
`ch592`, `ch595`).

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

**CH585 P4 real Host/GATT integration** (2026-11-09):
[`ch585-trouble-gatt`](examples/ch585-trouble-gatt) connects the event-level radio
pump to a bounded single-connection soft HCI/ACL bridge and real Trouble Host.
The native real-Host fixture passes discovery, read/write, notification, credit
recycling and reconnect tests. One controlled macOS physical cycle passed service
and characteristic discovery, five reads, thirteen writes, ten verified sequence
notifications, unsubscribe and normal disconnect, with a clean finite RF finish
and smoke recovery. Earlier failed attempts are retained. The successful run's
sniffer did not follow its data channel and required forced shutdown, so that
capture gate is not verified. Android/iPhone P4 acceptance, repeated physical
reconnects and sustained reliability are also unverified. See the example for the
finite runner and safety/recovery policy.

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
