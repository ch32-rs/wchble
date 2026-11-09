# CH585 P3 connect-only peripheral prototype

This finite LE 1M peripheral is a **prototype**, not a qualified BLE controller
or a general-purpose peripheral stack. It extends the P2 scannable advertiser
with connection establishment and bounded connection-event/LL-control handling.
The advertised local name is exactly `wch585-p3`.

There is **no GATT database, application service, pairing, or encryption**.
The macOS client deliberately calls neither `discoverServices` nor any GATT
operation after `didConnect`. CoreBluetooth/macOS can still initiate controller
LL procedures automatically; connect-only does not mean no LL traffic.
Unsupported requests and connection failures must be preserved as evidence,
not silently retried until a connection happens to work.

**Air IFS is unmeasured.** Firmware RX/TX counters, CoreBluetooth connection
callbacks, and a successful host hold are different observations. None proves
150-us inter-frame spacing, radio timing compliance, or full BLE conformance.
Independent over-the-air instrumentation is still required.

## Build the exact firmware to test

Build from this example directory, so its target/linker configuration applies.
The tools do not build firmware.

```sh
cd examples/ch585-peripheral
cargo build --release
```

The default firmware has a finite **25-second** run. Afterward it stops the RF
engine, records observations, and parks. A bounded stop failure parks with stage
`0xee` and is a failure, not a successful run.

For a **360-second** finite run instead, build explicitly with the feature.

```sh
cargo build --release --features long-run
```

Both builds use the same output path
`target/riscv32imc-unknown-none-elf/release/ch585-peripheral`. The ELF exports a
file-backed `RUN_SECONDS: u32`; the runner checks it offline against
`--run-seconds` before accessing hardware. A 360-second ELF with the runner's
25-second default is rejected rather than probed while still running.

Build the recovery image separately before running the test.

```sh
cd ../ch585-rf-smoke
cargo build --release
cd ../ch585-peripheral
```

No runner step rebuilds either image. It archives and flashes the exact
`firmware.elf` copy, plus archives the recovery `smoke.elf`, with SHA-256 hashes.

### RAM execution is part of this example's timing dependency

The working short-connection build depends on running the hot `main`,
`receive`, `run_connection`, and `transmit` paths in QingKe highcode RAM.
`receive` borrows the stopped RX buffer instead of copying 40 bytes before
handling the packet. Stopping RF before borrowing RX remains necessary for DMA
safety; moving code to RAM does not remove that requirement.

Moving only the Rust functions is insufficient: compiler-generated PDU copies
and zeroing can still call Flash-resident `compiler_builtins` memory routines.
`ram-mem.x` places those `memcpy`/`memset` input sections immediately after
`.highcode` in RAM and extends `_highcode_vma_end`, so the QingKe startup's
contiguous Flash-to-RAM copy initializes both regions. `build.rs` must pass
**`-Tram-mem.x` before `-Tlink.x`**. Preserve that linker order, the input-section
rules, and the startup-copy boundary when changing the build; treating this as
an optional optimization can reintroduce first-response `Late` failures.

The run06 ELF had `_highcode_vma_start` at `0x20000000` (vectors plus RAM code)
and approximately 17.7 KiB of RAM code. The reset/startup entry remains in
Flash; `main` runs in RAM. Those are observations about that exact build, not fixed layout promises
for later compiler/linker versions. Inspect each tested ELF and retain its hash.
RAM execution and the delay samples below still do not measure air IFS.

Before any hardware access, the runner validates the archived ELF's `memcpy`,
`memset`, `_highcode_vma_start`, `_highcode_vma_end`, and `_highcode_lma`
symbols. Both memory routines must be in the file-backed executable
`.highcode_mem` RAM section, within the startup-copy range, with at least four
file-backed bytes at each entry. Every `nm`-visible `compiler_builtins` memory
routine body must also be inside the file-backed RAM copy range, covering both
legacy `_ZN...` and nightly v0 `_R...` mangled names. A RAM entry stub that jumps
to a Flash-resident compiler memory body is rejected. `.highcode` and
`.highcode_mem` must cover that
whole range with contiguous VMAs and contiguous file offsets. A file-backed
executable `PT_LOAD` must map the complete range to the physical Flash load
address `_highcode_lma`. The accepted layout is recorded as `ram_layout` in
`result.json`; Flash memory routines, holes, a missing memory section, or a
mismatched load mapping fail preflight without touching the probe. This is an
ELF check rather than a top-level linker `ASSERT`: older LLD can evaluate such
an assertion before `INSERT` section reordering and reject a correct final map.

## Offline checks (no Bluetooth or probe access)

On macOS, CoreBluetooth and the Swift compiler are required for the typecheck.
Python tests mock every external command and client process, including the
compiler, Bluetooth scanner, flashing, and probe I/O.

```sh
swiftc -typecheck tools/central.swift
python3 -I tools/test_run.py
```

These checks do not demonstrate that a physical CH585 can establish or sustain
a link. Hardware validation results must come from a real run's saved evidence.

## Observed hardware result and remaining scope

On 2026-11-09, **run06 passed one short connect-only cycle**: one connection,
approximately **1.037 seconds** of client-observed hold, requested cancellation,
and normal disconnect. Firmware recorded 38 connection events, 38 data RX,
38 data TX, zero late transmissions, zero stop errors, and zero missed events.
SCAN_REQ/SCAN_RSP counts were 386/386; the smoke restoration and discovery check
also passed. The last data-path TX-entry delay sample was 11 us, not an air-IFS
measurement.

**Run07 also passed one 10-second hold with the same firmware**, followed by a
normal disconnect and successful smoke recovery. Firmware recorded 337 events,
337 data RX and 337 data TX; late transmissions, TX/RX errors, stop errors,
missed events, supervision failures, and first-event timeouts were zero.
SCAN_REQ/SCAN_RSP counts were 242/242. This was not an error-free RF observation:
34 bad-CRC and 140 bad-PDU observations remain in the statistics, and 212 trace
rows were overwritten by the bounded rolling tail. They are not erased by the
runner's passing result and do not establish air compliance.

Both runs used firmware SHA-256
`a52ac6e049a19b2c3ed39472e49f01ff07bc2e250712501f5f0e5818803e89b8`.
Their local evidence is retained at repository-root paths
`local-docs/research/experiments/ch585-p3-run-06/result.json` and
`local-docs/research/experiments/ch585-p3-run-07/result.json`, with accompanying
run artifacts. These research directories are local and intentionally not
committed to Git; they are not files supplied by a fresh checkout.

Run06 was the first passing short closed loop after the RAM-path changes.
Earlier run01/run03/run04/run05 received a first data packet but failed with
`Late`; run02 failed pre-flash stop verification and subsequently recovered
smoke successfully. Those failures must remain recorded separately, not be
relabelled as successful attempts because run06 passed.

**The ten-cycle run11 failed:** six 10-second cycles completed, but the seventh
connection unexpectedly timed out. The firmware remained in its event-preparation
wait after the 360-second budget; it did not finish cleanly. Smoke recovery and
macOS discovery passed. The original ELF/hash, client log and statistics remain
in `local-docs/research/experiments/ch585-p3-run-11/`; this is not a passing
reconnect or long-run result.

Investigation found an incorrect counter-width assumption: CH585 SysTick does
not provide the free-running 64-bit counter assumed by the original high/low/high
reader. The current example extends wrapping **32-bit low-word deltas in
software**, then converts them with `TickRate`. The single polling clock owner
must sample more often than one raw rollover (about 69–72 seconds at these clock
rates); this is not a general sleep-safe or interrupt-shared time driver. A host
regression models repeated raw-counter rollovers over six minutes.

**Run12 passed all ten 10-second connect/disconnect/reconnect cycles** after
this fix, using firmware SHA-256
`02b084b6234481e445e75fb23187f6b3aac03979ead46caf69340578d59d823e`.
Firmware finished its full 360-second budget in stage 9, with 3,369 events and
3,349 data RX/TX. TX late/errors, RX errors, stop errors, supervision failures,
first-event and local-terminate timeouts were zero. Ten valid connections and
ten terminations corroborated the client. Smoke recovery and discovery passed.
The retained diagnostics include 20 missed events, 581 bad-CRC and 3,035 bad-PDU
observations, plus 3,271 trace overwrites. Passing interoperability does not mean
zero RF errors. Evidence is local at
`local-docs/research/experiments/ch585-p3-run-12/`.

**Run13 did not pass joint 120-second acceptance**, despite a successful
120.022-second CoreBluetooth hold and expected disconnect using the same run12
ELF. Firmware trace corroborates a normal termination, but its local duration
was 119.885 seconds, below the runner's strict minimum. These independent clocks
are not precisely calibrated to each other; no tolerance was added to convert
this failure into a pass. At firmware time 156.046 seconds, after the requested
client session ended, another valid connection was accepted and subsequently
hit supervision timeout. Its initiator is not identified by the saved trace.
Consequently the aggregate records two links and one supervision timeout, and
run13 remains FAIL. Firmware finished the finite budget cleanly and smoke
recovery/discovery passed. Evidence is local at
`local-docs/research/experiments/ch585-p3-run-13/`.

The subsequent P2 hardware regression (`ch585-p2-regression-14`) passed:
177/177 valid scan requests/response completions, zero response-late/errors or
stop errors, and macOS discovery of the response-only name `wch585-p2`. P2 source
was unchanged; installation/recovery used the explicit P3 halt/idle guard. Smoke
was restored and discovered afterward; this is the final device state.

The commands below are test procedures, not additional acceptance claims. No
GATT, encryption, or air timing/conformance acceptance follows from these results.

## One bounded hardware run

The runner uses only the fixed WCH-Link probe
`1a86:8010:F93D8F067E10`, chip `CH585`, JTAG, and non-interactive `probe-rs`.
It expects `probe-rs`, `swiftc`, `swift`, and `llvm-nm` (default
`/opt/homebrew/opt/llvm/bin/llvm-nm`; override with `--nm`). macOS must have
Bluetooth enabled and permission granted to the launching application. A denied
permission or permission-prompt timeout is a test failure; grant access before
starting a new, separately recorded run.

Run this only when hardware access and the eventual recovery scan are intended.
Use a new output directory for each run.

```sh
python3 tools/run.py --out /tmp/ch585-p3-first-event \
  --cycles 1 --hold 1 --timeout 20
```

Defaults are `--run-seconds 25 --cycles 1 --hold 1 --timeout 20`.
`--timeout` is the client's **total** scan/connect/hold/disconnect budget, not a
per-cycle timeout. It must exceed `cycles * hold`, and `timeout + 3` must fit in
`run-seconds`. The additional headroom is for bounded client cleanup; hardware
recovery waits for the firmware independently.

For the long-run ELF, the ten 10-second cycles and the single 120-second hold
are **two separate runs**, each with its own firmware boot, artifacts, and
recovery. This keeps failures attributable and does not combine two acceptance
conditions into an automatic retry loop.

```sh
# Requires the ELF built with --features long-run.
python3 tools/run.py --out /tmp/ch585-p3-ten-cycles --run-seconds 360 \
  --cycles 10 --hold 10 --timeout 180

python3 tools/run.py --out /tmp/ch585-p3-one-long-hold --run-seconds 360 \
  --cycles 1 --hold 120 --timeout 160
```

The runner performs exactly one firmware download and one client session.
The client only accepts an advertisement's **exact current local name**
`wch585-p3`; it never falls back to cached `peripheral.name`. It locks the first
matching macOS peripheral UUID for the whole session. That UUID is not an
on-air BLE address. Each hold uses a monotonic clock starting at `didConnect`.
An unexpected disconnect fails immediately. After a requested cancel, the
client waits for `didDisconnect` before counting the cycle or scanning for the
next one; connection failures are not silently retried. Its JSONL summary and
process exit status both indicate failure on incomplete cycles.

For standalone client use (this does not manage firmware or recovery), compile
and run the connect-only tool explicitly.

```sh
swiftc tools/central.swift -o /tmp/ch585-p3-central
/tmp/ch585-p3-central --cycles 1 --hold 1 --timeout 20
```

This standalone invocation does access Bluetooth. Do not confuse it with the
`swiftc -typecheck` offline check.

## Execution, recovery, and evidence

1. Archive both ELFs and hashes; save `llvm-nm` output and symbol addresses;
   validate the archived ELF's contiguous RAM startup-copy layout and embedded
   finite-run budget; compile a saved copy of the client.
2. Explicitly halt the CPU in one debug session, verify its reported halted
   state, then verify/stop the previously running RF engine using the existing
   P2 stop policy and its two idle checks. Download/verify/start the archived P3
   ELF only after that succeeds.
3. Run the client once. **Do not issue probe reads, writes, `info`, or other
   intrusive debug commands while the firmware is executing.**
4. Even if the client exits early or fails, wait at least `RUN_SECONDS + 3`
   seconds after the download command returns before reading observations.
   A download failure also takes this path because it may have started firmware.
5. Read `STATS` and the valid `TRACE` rows once the finite run is over. Cross-check
   firmware completion and link/data evidence against the exact requested
   client cycles/holds, not just a zero client exit status.
6. In cleanup, repeat the explicit CPU halt and RF stop/idle checks, then
   download/verify/start the archived smoke ELF and scan for the exact recovery
   name `wch585`. A failed recovery makes the whole run fail; it does not erase
   the original test failure.

The P3-only `halt_and_idle` precondition runs
`/usr/bin/script -q /dev/null probe-rs debug` with the fixed probe arguments and
`-c break -c quit`, with a 15-second timeout. The macOS `script` wrapper allocates
a PTY because this probe-rs debug CLI constructs its Readline editor even after
processing `quit`; a non-TTY invocation can otherwise panic with `Device not
configured`. The wrapper executes the command argv directly, not an interactive
shell, and propagates the child's exit status. A panic exit `101` is still a
failure even if an earlier line reported a successful halt. It does not use
`--launch`, reset, or a continue command. In the verified local probe-rs build
`b580f1a0b`, argument-free `break` halts the core and prints
`Stopped on your request[ at <PC/source>].`; `quit` suspends on disconnect.
The runner strips optional ANSI styling and requires that explicit positive
halt status before invoking the unchanged P2 RF-stop helper. A zero process
exit or `Debug Session Terminated` alone is insufficient. Both downloads use
`check_idle=False` because `halt_and_idle` has already performed the RF stop
and two checks, rather than running the old idle operation twice.
`test-halt.log`/`restore-halt.log` and their command records preserve this step;
failure or missing confirmation prevents the corresponding download. This
precondition's source/mocked-test checks do not substitute for hardware
verification of the new flow.

This is verified-idle debug boot, **not a physical power cycle**. If bounded
stop/idle verification fails, the helper refuses to flash. A preflight failure
before hardware access does not flash or scan anything. Test/client/observation
failures after hardware access still attempt recovery; no automatic repeat can
turn a failed run into a reported pass.

Artifacts in the selected output directory include the exact ELFs, hashes and
symbol addresses in `result.json`, `symbols.txt`, command records and logs,
`central.swift`, the compiled `central`, `central.jsonl`, `central.stderr.log`,
`stats.txt`/`stats.json`, `trace.txt`/`trace.json`, and recovery logs. Some
artifacts are necessarily absent when their producing step fails; the failure
remains in `result.json`. Keep the whole directory, including failed runs.

`STATS` is 64 little-endian `u32` words: magic `0x50333538`, version `1`, finished
stage `9`. Necessary completion checks include `CMD & 3 == 0`,
`MODE == 0x30000`, and `stop_err == 0`. A clean finish by itself is insufficient:
the client must complete exactly the requested cycles and monotonic holds,
and firmware must corroborate valid CONNECT requests, links with data, data
RX/TX, and termination. The `accepted` counter counts accepted data PDUs, not
accepted connections.
Diagnostics such as CRC errors, malformed PDUs, missed events, duplicates,
retries, unsupported control requests, and trace overflow remain visible in the
saved full statistics; their presence must not be described as air compliance.

The delay-profile fields `STATS[54..59]` are elapsed microseconds from the last
data packet's CPU-observed receive end to these checkpoints:

- `54`, `rx_stop_delay_us`: stop complete (`end-stop`).
- `55`, `rx_return_delay_us`: receive return (`end-return`).
- `56`, `tx_entry_delay_us`: transmit entry (`end-txentry`).
- `57`, `tx_return_delay_us`: transmit return (`end-txreturn`).
- `58`, `sequence_delay_us`: sequence handling complete (`end-sequence`).
- `59`, `handler_delay_us`: packet/control handler complete (`end-handler`).

Indices are unchanged. `STATS[60]` is now `terminate_timeout`: expiration of the
independent local-terminate deadline is fatal to runner acceptance. `61..63`
remain reserved. Earlier archived JSON retains its original `reserved_54`
through `reserved_60` keys where present and is not rewritten.

These are **the last data sample, not maxima** over the run, and CPU-observed
checkpoints are not independently measured on-air packet boundaries. A low
`end-txentry` value alone does not establish response IFS or worst-case latency.

`TRACE` contains 128 rows of eight `u32` values:
`(time_us, kind, event, channel, header, length, arg0, arg1)`.
The runner reads only `min(trace_count, 128) * 8` valid words; the raw read is
saved in physical slot order. The JSON view restores the order of the opening
64 rows followed by the most recent rolling 64-row tail. There can be a gap
between the opening and tail; this is not a complete event history.
`trace_count` is the total row count and can exceed 128; `trace_overflow` records
rolling overwrites and does not by itself fail a run. This bounded trace is not
an air sniffer and cannot establish on-air IFS.

The runner exits `0` only if the requested test, firmware checks, and smoke
recovery all pass; otherwise it exits nonzero. Hardware acceptance is limited
to the explicitly recorded runs above; passing offline tests alone does not
provide hardware evidence.
