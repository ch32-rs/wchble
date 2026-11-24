# CH582M LE 1M RF smoke test

This example exercises the CH582 polling radio with a non-connectable,
non-scannable advertisement on channels 37, 38, and 39. It opens a receive
window on each channel and reports TX completions, CRC-valid RX packets,
recognized peer advertisements, and window expirations. It also checks that
an already missed TX deadline returns `Error::Late`.

The board needs 32 MHz and 32.768 kHz crystals. The example selects the
external 32 kHz clock and leaves BLE interrupts masked. It uses UART1 TX on
PA9 at 115200 baud.

## Build and flash

Place [`ch5xx-hal`](https://github.com/ch32-rs/ch5xx-hal) beside the `wchble`
checkout. Follow its workspace requirements for `ch5xx-data`.

```sh
rustup target add riscv32imc-unknown-none-elf
cd examples/ch582-rf-smoke
cargo build --release
openocd -f /path/to/wch-riscv.cfg \
  -c 'program target/riscv32imc-unknown-none-elf/release/ch582-rf-smoke verify reset exit'
```

The OpenOCD command uses the WCH build and a WCH-Link in RISC-V mode.

## Verify over the air

1. Scan on a separate BLE radio for the name `wch582` and the random static
   address `C1:FF:EE:58:02:01`. On Linux, use `bluetoothctl --timeout 10 scan le`.
2. From the peer, advertise a payload containing the ASCII bytes `wch582-peer`.
   In an interactive `bluetoothctl` session, run:

   ```text
   menu advertise
   manufacturer 0xffff 0x77 0x63 0x68 0x35 0x38 0x32 0x2d 0x70 0x65 0x65 0x72
   back
   advertise broadcast
   ```

3. Watch the UART. Each channel line reports cumulative `tx`, `rx` and `peer`
   counts. `peer` should increase for each channel, and `rx timeouts` should
   increase while the peer is idle. End the peer session with
   `advertise off`.

Each TX count represents an LLE completion. The separate scanner verifies
over-the-air discovery. Per-channel TX reception and inter-frame timing
require a channel-aware sniffer. The example exercises raw RF in polling
mode. Link-layer events, connections and hardware encryption are outside its
scope.

## RF sequence provenance

The active register sequence and three-point calibration are based on the
public [ch32fun iSLER implementation](https://github.com/cnlohr/ch32fun/blob/master/extralibs/iSLER.h).
See the included [MIT notice](../../LICENSE-ch32fun).
