# CH585 RX / stop trace

Historical diagnostic instrument. Current P2 work and automatic warm-run
validation use [ch585-scannable](../ch585-scannable/README.md). Its normal workflow
checks/stops the RF explicitly and does not require a manual power cycle.
The cold-only instructions below describe this older isolated instrument.

P2 bring-up instrument, **not a scan responder**. One boot arms RX once,
observes raw register changes, calls the existing `shut()` once, samples again,
and parks. It never reads or reuses RX/TX DMA storage after arming, even after
shutdown. No closed BLE library or TMOS is linked. The shared backend and
original non-scannable smoke are unchanged.

The previous first-status snapshot could not distinguish a transient flag from
window expiry or engine shutdown. This version follows the whole interval and
keeps four shutdown checkpoints. It tests these specific hypotheses:

- Does a 10,000-half-us RX window reach zero, and does CMD change independently?
- Which raw LLE/BB flags appear before and after expiry?
- What changes immediately, 100 us and 5 ms after `shut()`?
- Does early cancellation differ from expiry followed by shutdown?

CMD low bits clearing is a **candidate observation**, not sufficient evidence
that DMA has drained. `shut()` currently reports no hardware completion condition.
Do not promote observations into a buffer-release API without a supported
completion/stop condition. All buffers remain quarantined until full power-off.

## Build and experiment matrix

Run commands from this directory. Requires the sibling `ch5xx-hal` checkout,
as does `../ch585-rf-smoke`.

| Build | Controlled comparison |
| --- | --- |
| `cargo build --release --features passive` | RX only, observe 20 ms then shut; first timeout/control run |
| `cargo build --release --features passive,early-stop` | RX only, shut at about 500 us, before the nominal 5-ms window |
| `cargo build --release` | One ADV_SCAN_IND on ch37, same RX window and 20-ms observation |
| `cargo build --release --features early-stop` | Same advertising run, early cancellation |

Each feature combination overwrites the ELF; archive the ELF and hash before
building the next. Repeat runs only with a fresh full power cycle each time.
`early-stop` does not ensure the engine is still receiving when shut is called:
a packet may have arrived earlier; inspect the pre-stop registers.
The passive control can run without an active scanner. Nearby advertising is
uncontrolled input, so absence of flags is not evidence of an RF failure.

All modes wait 2 s after initialization. Default mode transmits a single
`ADV_SCAN_IND`, static random AdvA C1:FF:EE:00:00:02, name `wch585`, on channel 37,
then uses the existing scanner RX path. No RAM trace writes are inserted between
TX return and RX arm. This path is not a verified fast advertiser turnaround;
one advertisement may miss a scanner's listening window. There is no BB capture
ISR/reload or LLE ISR/W1C consumer during observation. Missing completion cannot
be generalized to an IRQ-driven receive path.

## Flash / run / collect

Only use the positively identified CH585 probe. A debug reset is **not** a
substitute for a full power cycle. The inspected probe-rs `--cycle-power`
controls probe USB power, is unsupported on macOS, and cannot establish that
all target supplies and back-power paths are disconnected.

Flash and verify **without `--start`**, then fully disconnect/reconnect target
power (including back-power paths). Let firmware boot autonomously. Each run,
including after an error, requires that full power cycle. If complete power-off
cannot be established, record flash verification and RX experiment NOT RUN.
Do not reset/run the instrument repeatedly.

```sh
probe-rs info --verbose --protocol jtag --probe 1a86:8010:F93D8F067E10
probe-rs download --probe 1a86:8010:F93D8F067E10 --chip CH585 --protocol jtag \
  --verify target/riscv32imc-unknown-none-elf/release/ch585-scan-rx-once
# Fully power-cycle target; wait at least 3 seconds before any probe reads.
```

For advertising runs, start the scanner before power-on. macOS CoreBluetooth
cannot guarantee active scanning or prove SCAN_REQ transmission. Use a known
active scanner to test requests; radio capture is needed for air PDU/CRC/IFS.
No scan response is sent by any mode.

Collect only the observation buffers after the run; reads may halt the core.
Choose a RISC-V capable `nm` executable (e.g. WCH `riscv-none-embed-nm`). The
script fixes the probe serial, reads only the two named RAM symbols and saves
raw words plus CSV. It also retains the ELF hash, symbol addresses, probe
commands, diagnostic logs, and any partial binary read. Use the exact flashed ELF.

```sh
python3 tools/read_trace.py target/riscv32imc-unknown-none-elf/release/ch585-scan-rx-once \
  --nm /path/to/riscv-none-embed-nm --out /path/to/new-evidence-directory
```

Decoder zero exit status requires a complete, non-overflowed trace, successful
RX arm, ordered timestamps and all four terminal shutdown checkpoints;
it does not certify RX or DMA completion. Nonzero status preserves available
raw evidence. No debug reads during observation, no reading DMA memory, and no
resuming this boot after collection. Restore `../ch585-rf-smoke` with probe-rs
`download --verify`, power-cycle, and check macOS discovery before declaring
recovery complete. If power cannot be cycled, record recovery as unverified.

## Observation format (version 2)

`OBS` is 20 little-endian u32 words. Version 1's 12-word reader is obsolete.

| Word | Meaning |
| --- | --- |
| 0, 1 | Magic `0x52584f31`, version `2` |
| 2 | Stage: 1 HAL initialized; 2 RF initialized; 3 before TX; 6 RX armed; 9 error/park; 10 before shut; 11 trace complete/park |
| 3, 4 | TX / RX-arm result: 0 not attempted, 1 Ok, 2 Err |
| 5..9 | Final LLE IRQSTAT, BB IRQSTAT, CMD, WINDOW, elapsed us since RX-arm return |
| 10, 11 | Channel (37), pre-RX CMD |
| 12, 13 | Published complete rows, overflow flag |
| 14, 15 | Mode bits (0 passive, 1 early-stop), window in half-us |
| 16, 17 | TX-return to RX-arm-return CPU us, SysTick ticks per us |
| 18, 19 | Raw RESET_STATUS byte, TX-call CPU us (passive: branch overhead) |

`TRACE` holds at most 64 rows of 12 u32 words: elapsed us, phase, LLE IRQSTAT,
BB IRQSTAT, CMD, WINDOW, MODE, GUARD, BB RFCTRL, RFEND FECTRL, RXBUFPTR, raw
SysTick low counter. Phases: 1 observing, 2 immediately before shut, 3 immediately
after shut, 4 after a further 100 us, 5 after a further 5 ms. Rows are sequential
MMIO, not atomic snapshots. IRQSTAT/BB IRQSTAT/CMD transitions and a 1-ms
heartbeat trigger rows; WINDOW changes alone do not. Four rows are reserved for
shutdown checkpoints; overflow means transitions were lost.

Time derives from the low SysTick counter divided by measured ticks/us. These
short runs finish before wrap (about 71 s at 60 MHz); this is not a wrap-safe
long-running clock. RAM writes and MMIO reads perturb CPU timing. CPU TX/RX
gap, flags, window, and idle CMD do not prove packet-end timing, complete
SCAN_REQ, valid CRC, IFS, or DMA ownership release. RESET_STATUS is supplemental
evidence only; it does not replace the external power-cycle precondition.

Evidence-integrity tests (no probe access):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p 'test_*.py' -v
```
