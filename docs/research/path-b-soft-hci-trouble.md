# Path B refined — soft HCI + Trouble (Rust LL)

Date: 2026-11-04  
Choice: **self-written Rust link layer**, expose **in-process soft HCI** via `bt-hci`, run **Trouble** as Host.  
Radio HAL: keep / gradually wrap today’s `ch32v208-nimble` `wch_rf` (C), do **not** rewrite RF first.

## Goal shape

```
┌──────────────────────────────────────────────┐
│  Trouble (trouble-host)                      │  GAP/GATT/L2CAP/SM
├──────────────────────────────────────────────┤
│  soft HCI  = impl bt_hci::controller::*      │  in-memory queues, no UART
├──────────────────────────────────────────────┤
│  Rust LL   = adv/scan/conn state machines    │  NEW
├──────────────────────────────────────────────┤
│  PHY glue  = IFS / WFR / PHY mode            │  NEW (port ideas from ble_phy_wch.c)
├──────────────────────────────────────────────┤
│  wch_rf HAL (C → Rust FFI or rewrite later)  │  EXISTING, chip-specific
└──────────────────────────────────────────────┘
```

This matches Embassy’s intended split ([Trouble](https://github.com/embassy-rs/trouble) + [`bt-hci`](https://github.com/embassy-rs/bt-hci)): Host is reusable; chip differences stay below HCI.

Reference implementation of “C LL behind soft HCI” (pattern only — we are **not** keeping NimBLE LL long-term):
[`apache-nimble` `NimbleController`](https://github.com/benbrittain/apache-nimble-sys) used by Trouble’s [`examples/apache-nimble`](https://github.com/embassy-rs/trouble/tree/main/examples/apache-nimble).

---

## 1. Where soft HCI actually sits

Soft HCI is **not** a hardware block. It is:

1. `impl bt_hci::controller::Controller` — async `read` / `write_acl_data` / (sync/iso stubs OK early)
2. `impl ControllerCmdSync<C>` / `ControllerCmdAsync<C>` for every HCI command Trouble’s `Controller` supertrait demands
3. An event/ACL path from LL → Host (`ControllerToHostPacket`)

Trouble does **not** talk to your radio. It only calls those traits. See [embassy.dev/trouble](https://embassy.dev/trouble/).

### Packet flow (in-process)

```
Trouble runner
  │ exec(LeSetAdvEnable)     write_acl_data(...)
  ▼
SoftHci
  │ translate to LlApi       push to ll_rx_acl
  ▼
Rust LL task
  │ schedule radio           on PDU / conn events
  ▼
wch_rf_tx / wch_rf_rx
  │
  ▼ ISR / PHY callback
Rust LL
  │ encode HCI Event / ACL
  ▼
SoftHci event/ACL channel
  │ Controller::read()
  ▼
Trouble
```

Same topology as `NimbleController`: command lock + response channel + `READ_CHANNEL` for events/ACL, LL task drains work when Host has consumed prior packets.

---

## 2. What Trouble requires at the HCI boundary

Trouble’s host-facing alias `trouble_host::Controller` extends `bt_hci::controller::Controller` with a **large** set of `ControllerCmdSync` / `ControllerCmdAsync` bounds (`host/src/lib.rs`), including at least:

| Kind | Commands (non-exhaustive) |
| --- | --- |
| Base | `Reset`, `SetEventMask`, `SetEventMaskPage2`, `ReadBdAddr`, `ReadRssi`, `HostBufferSize`, `SetControllerToHostFlowControl`, `HostNumberOfCompletedPackets` |
| LE common | `LeSetEventMask`, `LeSetRandomAddr`, `LeReadBufferSize`, `LeReadFilterAcceptListSize`, `LeClearFilterAcceptList`, `LeAddDeviceToFilterAcceptList` |
| Legacy adv | `LeSetAdvParams`, `LeSetAdvData`, `LeSetScanResponseData`, `LeSetAdvEnable` |
| Ext adv/scan | `LeSetExtAdvEnable`, `LeSetExtScanEnable` (must typecheck even if you only use legacy first) |
| Conn | `Disconnect` (async), `LeConnUpdate` (async), `LeCreateConn` (async), `LeCreateConnCancel`, `LeSetScanEnable` |
| Feature gates | `SecurityCmds`, `SubratingCmds`, `IsoStreamCmds`, `ShortConnIntervalCmds` (often just extra `LeSetHostFeature*` when features on) |

Plus peripheral helper bounds in `peripheral.rs` / examples (filter list, scan rsp, …).

**Practical rule:**  
- Commands you **use** (legacy peripheral BAS): implement for real.  
- Commands required only by trait bounds: implement as **`Command Disallowed` / `Unsupported Feature`** until needed, *if* Trouble doesn’t call them on your feature set.  
- Validate against `examples/apps/ble_bas_peripheral.rs` first — that is the acceptance demo.

First demo wiring (from Trouble):

```rust
let mut resources: HostResources<DefaultPacketPool, 1, 2> = HostResources::new();
let stack = trouble_host::new(controller, &mut resources)
    .set_random_address(address)
    .build();
join(stack.runner().run(), peripheral_advertise_loop(...)).await;
```

---

## 3. Layer responsibilities (what we implement)

### L0 — `wch_rf` (keep)

Already proven on CH32V208:

- clocks / DevInit / TXCtune…
- basic TX/RX, IRQ, channel/AA/CRC/PHY bits

Work for Path B:

- Stable C ABI (`wch_rf.h`) for Rust `extern "C"`
- No HCI knowledge here
- Later: CH585/CH583 table packs behind the same ABI

### L1 — PHY scheduler glue (Rust, new)

Port the *policy* from `ble_phy_wch.c`, not the NimBLE includes:

- arm RX with WFR; on AA capture extend window
- soft T_IFS / response deadline after RX_DONE
- map LL “next PDU” into `wch_rf_tx_*` / `wch_rf_rx_*`
- timebase: Embassy `embassy-time` or existing 1 MHz cputime story

This layer must be **real-time safe** (ISR → signal LL; LL runs in high-priority executor task).

### L2 — Rust LL (new, the bulk)

Minimum viable peripheral LL:

1. Advertising sets (legacy first): params, adv data, scan rsp, enable/disable  
2. Accept `CONNECT_IND` → connection state machine  
3. Connection events: anchor, interval, channel map, CRC/AA, SN/NESN  
4. ACL fragment ↔ LL data PDUs  
5. Control PDUs as needed: `LL_FEATURE_REQ/RSP`, `LL_VERSION_IND`, `LL_LENGTH_*`, `LL_PHY_*` (can stage)  
6. Disconnect / supervision timeout  

Central/scan is phase-2+ unless you need it earlier.

**Do not** reimplement GATT here — Trouble owns Host.

### L3 — Soft HCI adapter (new, thinner than LL)

Owns:

- Serialize/deserialize `bt-hci` cmd/event/ACL types
- Cmd → `LlApi` method calls
- Ll events → HCI events (`Command Complete` / `Status`, `LE Advertising Set…`, `LE Connection Complete`, `Disconnection Complete`, `Number Of Completed Packets`, …)
- Flow control counters (`HostBufferSize`, `HostNumberOfCompletedPackets`)
- One-at-a-time cmd execution (same assumption as `NimbleController`) unless you build a deeper queue

Does **not** own radio timing.

### L4 — Trouble Host

Unmodified upstream. App copies `ble_bas_peripheral` pattern.

---

## 4. Recommended repo layout

```
wch-ble/                    # working name
  wch-rf/                   # FFI to C wch_rf OR gradual Rust port
  wch-phy/                  # IFS/WFR/scheduler on top of wch-rf
  wch-ll/                   # Rust link layer
  wch-hci/                  # bt-hci Controller + CmdSync/Async impls
  wch-firmware/             # Embassy binary: init RF → spawn LL → Trouble app
```

CH32V208 first; CH583/CH585 = swap `wch-rf` tables only if LL/HCI stay stable.

---

## 5. Phased delivery (acceptance gates)

### Phase A — Skeleton boots Trouble

- [ ] Embassy app links `bt-hci` + `trouble-host`
- [ ] `SoftHci` implements `Controller` + **all** compile-time `ControllerCmd*` bounds (stubs OK)
- [ ] Real: `Reset`, `ReadBdAddr`, `SetEventMask*`, `LeSetEventMask`, `LeSetRandomAddr`, `LeReadBufferSize`, `HostBufferSize`, `SetControllerToHostFlowControl`
- [ ] `runner.run()` stays alive; no panic on init cmd sequence

**Gate:** device powers up, Trouble completes host init against soft HCI.

### Phase B — Legacy advertise visible

- [ ] Real: `LeSetAdvParams/Data/ScanResponseData/Enable`
- [ ] LL adv state + `wch_rf` TX on 37/38/39
- [ ] Phone/Mac sees advertiser (name/manufacturer)

**Gate:** match current NimBLE project’s “Mac sees device” milestone.

### Phase C — Connect + GATT BAS

- [ ] Parse `CONNECT_IND`, start conn SM
- [ ] HCI `LE Connection Complete` + ACL path both directions
- [ ] Enough LL control for Trouble GATT (features/version/MTU/length as needed)
- [ ] `Disconnect` + supervision timeout
- [ ] Run Trouble `ble_bas_peripheral` (notify battery level)

**Gate:** nRF Connect / Mac read BAS; stable 5–10 min.

### Phase D — Hardening / parity

- [ ] DLE, 2M PHY, conn update
- [ ] Multi-packet ACL / `Number of Completed Packets` correctness under load
- [ ] Optional: ext adv, central/scan
- [ ] Port RF tables for CH583 (closest to V208) then CH585

---

## 6. Soft HCI design notes (concrete)

### Channels

Mirror the working NimBLE facade:

- `CMD_REPLY: Channel<EventBytes, 1>` — status / command complete for the in-flight cmd  
- `TO_HOST: Channel<(PacketKind, Buf), N>` — events + ACL to `Controller::read`  
- `cmd_lock` — single flight commands until LL is concurrent-safe  

### ACL

- Host → LL: `write_acl_data` → LL TX queue (conn handle, PB/BC flags, payload)  
- LL → Host: assemble HCI ACL from LL data PDUs; respect `HostBufferSize`  

ISO/Sync: stub `write_iso_data` / `write_sync_data` as errors until needed.

### Time & executor

- RF ISR: only stamp / push small events (no HCI encode in ISR)  
- LL task: high priority Embassy task  
- Trouble `runner`: separate task; never block RF  
- Avoid probe-rs/RTT while on-air (same lesson as V208 NimBLE bring-up)

### What soft HCI cannot paper over

- Wrong DevInit / VCO cal (CH585 vs V208)  
- Missed IFS / WFR  
- Conn-event scheduling bugs  

Those remain L0–L2 failures; HCI will only surface them as disconnects / timeouts.

---

## 7. Why not wrap NimBLE LL “temporarily”?

You explicitly chose **Rust LL**. Short note for the record:

| Approach | Pros | Cons |
| --- | --- | --- |
| Soft HCI on NimBLE LL (`apache-nimble` style) | Fastest Trouble bring-up | C LL forever; NPL/porting; fights “Rust controller” goal |
| Soft HCI on Rust LL (this plan) | Clean Embassy stack; per-chip RF only below | Must re-prove conn SM; longer to Phase C |

A **throwaway** NimBLE-LL facade could still be used as an HCI **integration test oracle** on desktop/UART, but production Path B target remains Rust LL.

---

## 8. Immediate next engineering steps

1. Create `wch-hci` crate skeleton: `SoftHci` + stub `ControllerCmd*` so `trouble_host::new` typechecks with `ble_bas_peripheral` bounds.  
2. FFI-bind `wch_rf_init` / TX / RX / ISR callbacks into a Rust `Radio` trait.  
3. Implement Phase A cmd set + empty LL task.  
4. Implement legacy adv only (Phase B) before any GATT ambition.  
5. Only then connection SM + ACL (Phase C).

---

## 9. Success criteria (Path B done)

- Trouble Host, no NimBLE Host, on CH32V208  
- Soft HCI in-process (`bt-hci` traits), not UART dongle  
- Rust LL + existing `wch_rf`  
- Peripheral BAS demo stable  
- Documented HCI command matrix: real vs stub  
- Clear porting surface for CH583/CH585 = RF tables only

## References

- [embassy-rs/trouble](https://github.com/embassy-rs/trouble) — Host + examples  
- [embassy.dev/trouble](https://embassy.dev/trouble/) — integration pattern  
- [embassy-rs/bt-hci](https://github.com/embassy-rs/bt-hci) — Controller traits / HCI types  
- [benbrittain/apache-nimble-sys](https://github.com/benbrittain/apache-nimble-sys) — soft HCI facade over NimBLE controller (reference)  
- Local RF: `~/Repos/ch32v208-nimble/drivers/wch_ble/`  
- Family init diffs: [`family-comparison.md`](family-comparison.md)
