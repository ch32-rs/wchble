# ch573-adv — legacy broadcaster

Advertises `ADV_IND` on channels 37/38/39 from a CH573, with a 20 ms
advertising interval and the 0–10 ms `advDelay` from the spec. The AD payload
is LE General Discoverable plus the complete local name `wch573`; the address
is the random `C1:FF:EE:00:00:73`.

## Scope

This is advertising only. After each PDU the radio goes back to the TX
schedule; there is no post-TX listen window, so `SCAN_REQ` and `CONNECT_IND`
are never answered. A peer that tries to connect times out on its side — the
link layer never rejects it — and the board keeps advertising.

`tx_basic` is polling-only: it masks the BLE lines, arms the LLE window,
mirrors the vendor bit9 kick from a tight poll, and treats the window drain
(`LLE+0x60 == 0`) as completion. An installed RX ISR cannot race it.

## Build and flash

```sh
cargo run --release          # probe 1a86:8010:5CED8F06E1D2, RTT via probe-rs
```

`DEFMT_LOG=info` is set in `.cargo/config.toml`. Expected start:

```
rf init ok
ADV_IND len=19 interval_us=20000 channels=3
connection not implemented: CONNECT_IND is not answered
adv round=0 event_us=1608 wait_us=23162 delay_us=21554
```

Every 50 events it logs the three values that define the cadence:

* `event_us` — time for the three channel PDUs, ~1.61 ms,
* `wait_us` — interval + advDelay for this event, always 20 000–30 000 µs,
* `delay_us` — the busy-wait actually spent, `wait_us - event_us`.

`tx ch.. err Timeout` means one channel's PDU was skipped (no
bit9 kick within 500 µs or no window drain); the scheduler still waits to
`t0 + wait`, so the event grid does not drift. Observed rate on the bench
board: a few per thousand PDUs.

## TX power

`CH573_ADV_TX_POWER` picks the level at build time (`-20 -14 -8 -4 0 1 2 3 4 5`,
default `0`):

```sh
CH573_ADV_TX_POWER=-20 cargo run --release
# tx_power=-20 dBm code=1
```

The example calls `radio.set_tx_power(...)` **before** `init()`; the driver
programs the level during `BB_DevInit`. It cannot be changed on a running
radio: the PA tune done at init is bound to it, and bench retuning to a lower
level after init left the output inaudible at 20 cm.

Silicon readback after init (`probe-rs read b32 0x4000c100 1`, RFCTRL
`[13:8]`):

| build | code | RFCTRL |
| --- | --- | --- |
| `-20` | `0x01` | `0x10000127` |
| `0` | `0x14` | `0x10001427` |
| `5` | `0x32` | `0x10003227` |

On air, every level decodes with the same PDU/channel timing (nRF sniffer
captures at 0 / +5 / -20 dBm: 2434 / 1922 / 1938 frames; macOS: 66 / 51 / 67
sightings). RSSI cannot grade the levels on this bench — the board sits
centimetres from the receivers, so both the sniffer (≈ −23 dBm) and macOS
(≈ −40 dBm) saturate.

## On-air acceptance

1. macOS discovery (independent of the board's own logs):

   ```sh
   swift ../ch573-rf-smoke/tools/scan_ch573.swift wch573 10
   ```

   Pass = repeated `seen name=wch573`. Bench run: 69 sightings in 10 s,
   mostly −41…−45 dBm.

2. nRF Sniffer capture plus `tools/adv_stats.py`:

   ```sh
   nrfutil ble-sniffer sniff --port /dev/tty.usbmodem… \
       --only-advertising --output-pcap-file adv.pcap
   python3 tools/adv_stats.py adv.pcap --addr C1:FF:EE:00:00:73
   ```

   Pass = type `0x00`, AdvA `C1:FF:EE:00:00:73`, AD `01 06` + `09 "wch573"`,
   channels split across 37/38/39, intra-event gaps ≪ 10 ms, and same-channel
   deltas clustering at 20–30 ms. The sniffer is lossy; a dropped event makes
   one delta an integer multiple, so judge the cluster and the percentiles, not the
   maximum. The board's `wait_us` log is the primary interval evidence.

   Bench capture (`/tmp/ch573-adv.pcap`, 16 s): 1368 of our PDUs,
   intra-event gaps median 0.54 ms, same-channel medians 25.7–29.6 ms, and
   54–85 % of same-channel deltas inside 20–30 ms per channel. The rest are
   mostly integer multiples from dropped events; one 10.3 ms sample looks like
   a sniffer timestamp glitch rather than a short interval.

A phone-side connect attempt is expected to time out (nothing answers the
`CONNECT_IND`); it was not part of this round's evidence.
