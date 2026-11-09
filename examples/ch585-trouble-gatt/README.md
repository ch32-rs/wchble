# CH585 Trouble GATT peripheral (P4)

This example combines the CH585 polling radio/LL with the real `trouble-host`
GATT server. It is not the P3 hand-written ATT responder. One controlled macOS
physical GATT cycle passed (2026-11-09); this is not Android/iPhone acceptance,
repeated physical reconnect validation, sustained stability, or air compliance.

The local Trouble checkout at `../../../trouble/host` must be at
`3aa6fd27b89cd5fc35f5c9b4f0c7f66795a14f70` (the `bt-hci` 0.11 revision).
Only `peripheral`, `gatt`, `default-packet-pool` and
`default-packet-pool-mtu-27` are enabled. No derive macros, executor, or HAL
Embassy/SysTick time driver are enabled. The build and RAM-copy linker fragment
are inherited from the P3 peripheral example.

Keep this executable's `Cargo.lock` under version control and archive it with
build artifacts. It pins the transitive `uuid` dependency to `1.17.0`, matching
the existing Trouble advertising example and the repository's Rust 1.88
toolchain. A newly resolved `uuid` 1.29.2 requires Rust 1.89 and does not build
with Rust 1.88. Reproduce the dependency graph with
`cargo build --release --locked`; do not delete or regenerate the lockfile as
part of normal builds.
If intentionally recreating it, run `cargo update -p uuid --precise 1.17.0`
before building. The local Trouble checkout revision above must also match.

## Validation status

The controlled macOS cycle completed discovery, five reads, thirteen writes,
ten checked notifications (101–110), unsubscribe, final readback 110, and expected
disconnect. Firmware recorded 65 data RX/TX, three missed events, normal terminate
0x13, no supervision expiration, TX late/error, RF stop error, Host/bridge error,
or Host poll overrun. Maximum observed Host/HCI poll was 985 us; the finite
25-second run ended safely and smoke restoration/discovery passed. This is an
observed maximum from one run, not a worst-case execution bound.

Two earlier attempts failed during automatic discovery and are retained as
failures. The final fix keeps Host polling outside the existing 2 ms guard and
uses a tight RF-only wait to the unchanged RX prepare deadline, rather than
repeated outer-loop snapshots that can overshoot it. Channel setup is also done
early, as in P3. Trace kind 8 records RX arm entry/return times outside the
RX-to-TX response deadline.

The successful functional run's optional sniffer capture did **not** follow data
channels and needed forced shutdown. It does not independently verify that cycle's
ATT packets or air timing; client and firmware evidence establish the functional
result. Earlier failed captures did observe actual Trouble MTU/service replies.
No multi-round physical reconnect, Android/iPhone P4, long-run P4, or calibrated
IFS acceptance is claimed.

## GATT contract

- Complete local name: `wch585-p4`.
- Static random address: `C1:FF:EE:00:00:14`.
- GAP service `1800`: Device Name `2A00` and Appearance `2A01` (unknown, zero).
- GATT service `1801`.
- Custom service: `00001000-b0cd-11ec-871f-d45ddf138840`.
- Value characteristic: `00001001-b0cd-11ec-871f-d45ddf138840`.
- Value properties: Read, Write (with response), Notify; CCCD managed by Trouble.
- Value encoding: exactly four bytes, unsigned 32-bit little-endian, initially 0.

The client writes sequence number `n`; readback and each subscribed notification
contain the same `n`, not an independently generated counter. The payload is
four bytes, below the 20-byte ATT payload budget at MTU 23. With notifications
disabled, writes and reads continue normally. Disconnection returns to
advertising; the characteristic value persists for the life of the host future.
The client should enable notifications anew after reconnecting.

The UUID text constants and the corresponding ATT little-endian `Uuid` constants
are exported by `src/host.rs`; clients should use the text form above rather than
formatting the constructor's raw byte array in forward order.

## Host integration and diagnostics

`host::run(controller, &stats)` is one persistent future. Main owns a local
`HostStats`, pins the future once, and polls it only outside radio deadlines.
The host joins Trouble's runner with the advertising/GATT application; no host
poll is allowed to re-enter RF handling. Fatal host/application errors record the
stage and then remain pending instead of spinning inside `poll()`.

`HostStats::word(index)` exposes these single-threaded `Cell` values for archival
by the radio main loop; out-of-range indices return zero.

| Word | Meaning |
| --- | --- |
| 0 | Phase: 0 unpolled, 1 starting, 2 advertising, 3 connected, 255 fatal |
| 1 | Accepted connections |
| 2 | Observed disconnections |
| 3 | Reads of the custom value |
| 4 | Accepted writes to the custom value |
| 5 | Notifications queued by Trouble, not central acknowledgements |
| 6 | Last custom value written |
| 7 | Errors |
| 8 | Last error stage |
| 9 | Other GATT events, including discovery and CCCD access |
| 10 | Current connection's notification subscription (0/1) |
| 11 | Advertising attempts |

Error stages: 1 runner exit, 2 advertising-data encode, 3 scan-response encode,
4 advertise, 5 accept, 6 attribute-server attachment, 7 GATT accept, 8 value
readback, 9 notify, 10 connection-parameter rejection. Stages 9 and 10 are
non-fatal; other stages park the failing task. A malformed/rejected ATT request
that Trouble successfully answers is not itself a host error.

The exported `STATS[64]` retains the P3 radio counters, with P4 magic
`0x50343538`; word 31 is RX backpressure (not automatically a fatal error).
Words 61–63 record the maximum single Host/HCI poll duration in microseconds,
poll deadline overruns, and bridge invariant errors. `HOST_STATS[16]` snapshots
the twelve Host counters above, followed by four reserved zero words. A 2 ms
pre-poll guard is not a preemptible execution budget; actual poll duration and
wireless deadlines must still be checked on hardware.

## Build and validate

Build from this directory with `cargo build --release --locked`. The default
image has a finite 25-second RF budget; `--features long-run` selects 360 seconds.
The runner checks `RUN_SECONDS` in the exact archived ELF before touching hardware.

Run the native real-Trouble fixture **from the repository root**, avoiding this
example's embedded target configuration:

```sh
cargo test --locked --manifest-path tests/trouble-host/Cargo.toml
python3 examples/ch585-trouble-gatt/tools/test_run.py
swiftc -typecheck examples/ch585-trouble-gatt/tools/central.swift
```

The native fixture covers service/characteristic/CCCD discovery, read/write and
readback, notifications 101–110, more than five real ACL credit cycles, disconnect
with an unacknowledged packet, same-handle reconnect, and subscription reset. It
runs the actual `host::run` and soft HCI bridge, not the radio or a physical client.

On macOS, one controlled physical GATT cycle can be run from the repository root:

```sh
python3 examples/ch585-trouble-gatt/tools/run.py \
  --out local-docs/research/experiments/ch585-p4-unique-run \
  --run-seconds 25 --cycles 1 --timeout 20
```

Use a new output directory for every attempt. This command flashes the fixed
probe `1a86:8010:F93D8F067E10`, archives both ELF images and their hashes, runs the
CoreBluetooth client, waits the complete finite budget plus three seconds before
probe reads, and finally restores smoke and checks exact-name `wch585` discovery.
A failed run is retained, not automatically retried. The client discovers the
custom service and characteristic, performs three write/readback pairs, subscribes
and checks ten numbered notifications, unsubscribes, reads back 110, and waits for
its expected disconnect. No phone client should run concurrently.

The runner does not start the optional nRF Sniffer itself. Capture its separate
`C1:FF:EE:00:00:14 random` target before flashing when air evidence is required.
Build/native success, macOS GATT acceptance, Android/iPhone acceptance, sustained
reliability, and calibrated air timing are separate validation claims.
