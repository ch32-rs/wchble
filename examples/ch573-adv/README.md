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

An occasional `tx ch.. err Timeout` means one channel's PDU was skipped (no
bit9 kick within 500 µs or no window drain); the scheduler still waits to
`t0 + wait`, so the event grid does not drift. Observed rate on the bench
board: a few per thousand PDUs.

## On-air acceptance

1. macOS discovery (independent of the board's own logs):

   ```sh
   swift ../ch573-rf-smoke/tools/scan_ch573.swift wch573 10
   ```

   Pass = repeated `seen name=wch573`.

2. nRF Sniffer capture plus `tools/adv_stats.py`:

   ```sh
   nrfutil ble-sniffer sniff --port /dev/tty.usbmodem… \
       --only-advertising --output-pcap-file adv.pcap
   python3 tools/adv_stats.py adv.pcap --addr C1:FF:EE:00:00:73
   ```

   Pass = type `0x00`, AdvA `C1:FF:EE:00:00:73`, AD `01 06` + `09 "wch573"`,
   channels split across 37/38/39, intra-event gaps ≪ 10 ms, and same-channel
   deltas clustering at 20–30 ms. The sniffer is lossy; a dropped event makes
   one delta an integer multiple, so judge the cluster and the minimum, not the
   maximum. The board's `wait_us` log is the primary interval evidence.

   Bench capture (`/tmp/ch573-adv.pcap`, 16 s): 1368 of our PDUs,
   intra-event gaps median 0.54 ms, same-channel minimum 20.16 ms,
   54–85 % of same-channel deltas inside 20–30 ms (the rest are multiples
   caused by sniffer loss).

A phone-side connect attempt is expected to time out (nothing answers the
`CONNECT_IND`); it was not part of this round's evidence.
