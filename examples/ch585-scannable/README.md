# CH585 scannable broadcaster (P2)

Finite 8-second ADV_SCAN_IND → SCAN_REQ → SCAN_RSP experiment on channels
37/38/39, followed by checked RF shutdown and park. Not connectable.

Reuses the event flow from the working `ch32v208-nimble` open PHY:
TX completion → bounded RX/WFR; address capture extends the packet budget;
completed packets are CRC/address/type/length checked; a response uses an
absolute RX_DONE-based TX deadline; partial/empty RX closes and the next
advertising event runs. The existing CH585 RF backend supplies chip-specific
registers/calibration. No vendor BLE library or TMOS is linked. This example
implements only the P2 exchange, not the entire NimBLE Controller/Host.

AdvA is C1:FF:EE:00:00:12. Advertisement data contains flags only. The name
`wch585-p2` is **only in SCAN_RSP**. Receiving that exact name and recording
valid requests/responses provides an interoperability check. CoreBluetooth does
not guarantee active scanning; absence of requests alone is inconclusive.

The 120-us RX_DONE-to-TX-command starting point follows the V208 PHY. It is
an experimental CH585 setting, not measured air IFS. Register setup precedes
the absolute deadline; scheduled CH585 `tx_basic` skips the advertising-only
60-us pre-arm, following V208 basic-TX ordering. Late attempts are counted.
No logs, allocation or task scheduling occur in the RF loop.

## Build and automatic test

Requires sibling `../../../ch5xx-hal`, probe-rs, Swift/CoreBluetooth, and a
RISC-V capable nm. Build both the test and recovery images:

```sh
cargo build --release
(cd ../ch585-rf-smoke && cargo build --release)
python3 tools/run.py --out /path/to/new-evidence-directory
```

The runner uses only probe **1a86:8010:F93D8F067E10** and CH585/JTAG. It
explicitly stops an active CH585 engine using the backend shutdown sequence,
checks idle CMD twice before overwriting memory, downloads with verify/start, runs
without probe reads, scans for the response-only name, captures counters,
then restores the smoke and checks discovery. Override `--nm` if needed.
Normal test iterations use debug boot from a stopped radio, without manual
power cycling. An unacknowledged stop prevents flashing; WINDOW expiry is not
a stop acknowledgement. Recovery failure remains a failure.

The firmware uses the V208 shutdown policy with a bounded CH585 CMD idle
acknowledgement and memory fence before CPU RX access/reuse. All DMA storage is
static and exclusively owned for the boot. Stop failure parks without reuse.
This is an experimental board-tested ownership policy, not a new guarantee for
the general `Radio::rx_basic` API. No other chip's backend is modified.

## Verified milestone (2026-11-09)

Three runs on the identified CH585, with macOS 15.6.1 and probe-rs 0.32.0:

| Run | Valid SCAN_REQ | SCAN_RSP TX complete | Response-name reports | Smoke reports after restoration |
| --- | --- | --- | --- | --- |
| 1 | 135 | 135 | 118 | 12 |
| 2 | 127 | 127 | 120 | 15 |
| 3 | 122 | 122 | 106 | 20 |

All runs finished normally with zero late responses, other response errors,
stop failures or RX-arm errors. Each sent 1053 advertisements and restored the
non-scannable smoke. Counts of CoreBluetooth reports are distinct from RF
packet counts. The host suite passed 12 tests, including malformed request
rejection; both examples built in release mode.

This is the working P2 functional prototype. Controlled invalid-request air
injection, per-channel receive coverage, independent air IFS measurements,
iPhone interoperability and long-running stability remain unverified. The user
also confirmed Android scan visibility; obtaining the response-only data on
Android was not separately instrumented. macOS results support an iPhone
compatibility expectation, but are not an independent iPhone test.
The initial attempt received 155 valid requests but all responses were late;
the scheduled-TX pre-arm change fixed that failure. No claim of connection or
GATT support on CH585 follows from this milestone.

## Counter layout

STATS: 32 u32 words; magic `0x50323538`, version 1.

| Word | Meaning |
| --- | --- |
| 2 | Stage: 1 init, 2 ready, 3 TX, 4 RX, 5 response, 9 finished; e1 init failure, ee stop failure |
| 3..5 | Advertisement attempts, TX completions, TX errors |
| 6..10 | RX arms, timeouts, completion flags, CRC errors, other/invalid packets |
| 11..15 | Valid target SCAN_REQ, completed SCAN_RSP TX calls, acknowledged stops, stop failures, RX arm errors |
| 16..19 | Captures, partial timeouts, late responses, other response errors |
| 20..21 | Last raw LLE/BB status |
| 22..25 | Run us, SysTick ticks/us, response delay us, last completed payload length |
| 26..27 | Final CMD and MODE |

LAST_REQ stores the last validated 14-byte SCAN_REQ. Probe reads happen only
after the finite experiment; installed CLI versions may halt **and resume** the
core. Internal TX completion is not proof of air transmission. CRC/channel/IFS
on air and stability require separate measurements. Do not call the stage
complete solely because this builds or a TX counter advances.
