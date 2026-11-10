# Android GATT peripheral for the CH585 C1 central test

Self-contained Android test app (no Gradle, no network) that acts as the
controlled peripheral for the `ch585-central` firmware:

- legacy connectable/scannable `ADV_IND` advertising via `BluetoothLeAdvertiser`
- the complete local name (default `wch585-c1`) is inside the advertising PDU
- one primary service `00001000-b0cd-11ec-871f-d45ddf138840`
- one characteristic `00001001-b0cd-11ec-871f-d45ddf138840`
  (READ | WRITE | NOTIFY, permissions READ | WRITE)
- initial value: u32 `0x0000002A` little-endian
- writes store the first four bytes as a little-endian u32 and are answered
  with success; reads return the current value at the requested offset and
  answer `0x07` (`GATT_INVALID_OFFSET`) for an out-of-range offset
- a small delay after every disconnect restarts advertising (`readvertising`)

## Build

Requires a JDK plus an installed Android SDK with `build-tools/35.0.0` and
`platforms/android-35` (the same toolchain as the sibling advertiser app).
Nothing is downloaded.

```sh
./build.sh
```

Environment overrides: `JAVA_HOME`, `ANDROID_SDK_ROOT` / `ANDROID_HOME`,
`ANDROID_BUILD_TOOLS`, `ANDROID_PLATFORM`. The last line printed is the APK
path: `build/android-gatt.apk`.

## Install

```sh
adb install -r -g build/android-gatt.apk
```

`-g` pre-grants `BLUETOOTH_ADVERTISE` and `BLUETOOTH_CONNECT` on Android 12+.
If the ROM refuses shell grants, the app requests them once at startup.

## Run

Default positive phase (90 s):

```sh
adb shell am start -n com.example.wchble.gatt/.MainActivity \
    --es name wch585-c1 --ei timeout 90
```

Wrong-name negative phase (the C1 must not connect):

```sh
adb shell am start -n com.example.wchble.gatt/.MainActivity \
    --es name wch585-c1-neg --ei timeout 90
```

No-service negative phase (connection succeeds, discovery finds no `0x1000`
service):

```sh
adb shell am start -n com.example.wchble.gatt/.MainActivity \
    --es name wch585-c1 --ez no_service true --ei timeout 90
```

Any combination works, including
`--es name wch585-c1-neg --ez no_service true`.

Intent extras:

| extra        | type    | default     | meaning                                   |
|--------------|---------|-------------|-------------------------------------------|
| `name`       | string  | `wch585-c1` | local name, also used in advertising data |
| `no_service` | boolean | `false`     | do not publish the service                |
| `timeout`    | int     | `90`        | seconds until stop + summary + `finish()` |

The app sets the adapter name (waits briefly for the asynchronous update) and
then advertises with `setIncludeDeviceName(true)`.

## Logs

```sh
adb logcat -s WCHBLE
```

One JSON object per line, all with `monotonic_ms` (milliseconds since the
activity started). Events: `start`, `adapter_name`, `permission_request`,
`advertising`, `advertise_failed`, `connected`, `disconnected`, `read`,
`write`, `service_added`, `readvertising`, `error`, `summary`.

Example lines:

```json
{"event":"connected","address":"AA:BB:CC:DD:EE:FF","status":0,"connections":1,"monotonic_ms":4210}
{"event":"read","address":"AA:BB:CC:DD:EE:FF","value":42,"value_hex":"0x0000002a","offset":0,"length":4,"status":0,"sent":true,"reads":1,"monotonic_ms":4300}
{"event":"write","address":"AA:BB:CC:DD:EE:FF","value":43,"value_hex":"0x0000002b","bytes":4,"offset":0,"prepared":false,"response_needed":true,"status":0,"writes":1,"monotonic_ms":4500}
{"event":"read","address":"AA:BB:CC:DD:EE:FF","value":43,"value_hex":"0x0000002b","offset":0,"length":4,"status":0,"sent":true,"reads":2,"monotonic_ms":4700}
{"event":"disconnected","address":"AA:BB:CC:DD:EE:FF","status":0,"connections":1,"disconnections":1,"monotonic_ms":5000}
{"event":"readvertising","name":"wch585-c1","attempt":1,"adv_bytes":14,"monotonic_ms":5750}
```

## 31-byte advertising constraint

The CH585 scans passively (legacy LE 1M), so it only sees the advertising PDU
and never the scan response. The complete local name must therefore be inside
`ADV_IND`.

Legacy advertising data is limited to 31 bytes:

- Flags element: 3 bytes
- Complete Local Name element for `wch585-c1`: 2 + 9 = 11 bytes
- Total: 14 bytes

The app uses `setIncludeDeviceName(true)` and deliberately adds **no**
128-bit service UUID and **no** TX power element. A single 128-bit UUID is 18
bytes and would push the name into the scan response. Connectable legacy
advertising selects `ADV_IND` (connectable + scannable), exactly what the
passive scanner needs.

The app pre-computes the payload size from the configured name. If a longer
`--es name` would exceed 31 bytes it logs `advertise_failed` with
`ADVERTISE_FAILED_DATA_TOO_LARGE` before starting; the framework callback with
the same code is also handled and logged.

## Notes

- `no_service` still opens a GATT server and accepts connections; it just
  publishes no attribute, so service discovery returns nothing.
- The characteristic keeps its current value across connection cycles, as a
  real peripheral would.
- The activity stays on screen (`FLAG_KEEP_SCREEN_ON`) for the length of the
  run. At the timeout it stops advertising, closes the GATT server, logs a
  `summary`, and calls `finish()`.
- Run one phase at a time. Wait for the `summary` line before launching the
  next phase (or `adb shell am force-stop com.example.wchble.gatt`), otherwise
  two advertising/GATT instances can overlap.
- The app changes the phone's Bluetooth adapter name (required because
  `setIncludeDeviceName(true)` uses the adapter name). It remains set to the
  last phase's name after the run.
