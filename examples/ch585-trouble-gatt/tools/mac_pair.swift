// Bond-B app: pairs the Mac with the pp peripheral's Security Request.
//
// macOS never lists an unknown-service BLE peripheral in System Settings
// (verified: 4 minutes of idle advertising, no row), and a CLI central
// without an app bundle cannot present pairing consent — the SMP exchange
// stalls at PairingResponse with no dialog. This is a regular .app: it
// activates itself and keeps a status window frontmost while the firmware's
// 2 s Security Request lands, so the system consent has an app context.
//
// The app only needs to make the pairing possible; the archival pp GATT
// evidence still comes from `central --mode pp` afterwards.
//
// Usage: MacPair [--timeout SECONDS] [--name wch585-p4]
// Output: JSONL on stdout. Exit 0 when the bond landed, 6 on timeout.
//
// Local build (the .app binary is git-ignored, never commit it):
//   mkdir -p MacPair.app/Contents/MacOS
//   cp mac_pair.Info.plist MacPair.app/Contents/Info.plist
//   swiftc -O -o MacPair.app/Contents/MacOS/MacPair mac_pair.swift

import Cocoa
import CoreBluetooth

var targetName = "wch585-p4"
var timeoutSeconds = 120.0
var arguments = Array(CommandLine.arguments.dropFirst())
while !arguments.isEmpty {
    let flag = arguments.removeFirst()
    switch flag {
    case "--timeout": timeoutSeconds = Double(arguments.removeFirst()) ?? 120
    case "--name": targetName = arguments.removeFirst()
    default: break
    }
}

let serviceID = CBUUID(string: "00001000-b0cd-11ec-871f-d45ddf138840")
let valueID = CBUUID(string: "00001001-b0cd-11ec-871f-d45ddf138840")

func monotonic() -> Double {
    Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
}

func emit(_ event: String, _ fields: [String: Any] = [:]) {
    var row = fields
    row["event"] = event
    row["monotonic_seconds"] = monotonic()
    if let data = try? JSONSerialization.data(withJSONObject: row,
                                              options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate,
                         CBCentralManagerDelegate, CBPeripheralDelegate {
    var manager: CBCentralManager!
    var peripheral: CBPeripheral?
    var characteristic: CBCharacteristic?
    var started = monotonic()
    var reads = 0
    var statusWindow: NSWindow?
    var statusLabel: NSTextField?

    func applicationDidFinishLaunching(_ notification: Notification) {
        emit("start", ["name": targetName, "timeout_seconds": timeoutSeconds])
        signal(SIGTERM) { _ in exit(0) }
        signal(SIGINT) { _ in exit(0) }
        // A windowless app never gets real activation, and a background
        // process cannot own the pairing consent: keep a floating status
        // window frontmost for the whole bonding window.
        let window = NSWindow(
            contentRect: NSRect(x: 560, y: 400, width: 360, height: 64),
            styleMask: [.borderless], backing: .buffered, defer: false)
        window.level = .floating
        window.title = "MacPair"
        let label = NSTextField(labelWithString: "MacPair: bonding \(targetName)…")
        label.font = NSFont.systemFont(ofSize: 14, weight: .medium)
        label.frame = NSRect(x: 16, y: 20, width: 328, height: 24)
        let view = NSView(frame: window.contentRect(forFrameRect: window.frame))
        view.addSubview(label)
        window.contentView = view
        window.orderFrontRegardless()
        statusWindow = window
        statusLabel = label
        NSApp.activate(ignoringOtherApps: true)
        manager = CBCentralManager(delegate: self, queue: nil,
                                    options: [CBCentralManagerOptionShowPowerAlertKey: true])
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            self.tick()
        }
    }

    func setStatus(_ text: String) {
        statusLabel?.stringValue = text
    }

    func tick() {
        if monotonic() - started >= timeoutSeconds {
            emit("timeout", ["phase": "waiting"])
            exit(6)
        }
    }

    func activate() {
        // The consent dialog needs a foreground app context; the floating
        // status window keeps this app genuinely frontmost.
        statusWindow?.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            emit("bluetooth_state", ["state": String(describing: central.state)])
            if central.state == .unsupported { exit(3) }
            return
        }
        emit("bluetooth_state", ["state": "poweredOn"])
        central.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        emit("scan_started")
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard peripheral.name == targetName else { return }
        emit("found", ["name": peripheral.name ?? "", "rssi": RSSI.intValue])
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral)
        emit("connecting")
        setStatus("MacPair: connecting \(targetName)…")
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        emit("connected")
        activate()
        setStatus("MacPair: paired? waiting for consent on \(targetName)…")
        peripheral.discoverServices([serviceID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                         error: Error?) {
        emit("connect_failed", ["error": error.map(String.init(describing:)) ?? ""])
        exit(5)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        emit("disconnected", ["error": error.map(String.init(describing:)) ?? ""])
        exit(7)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peripheral.services?.first else {
            emit("services_failed", ["error": error.map(String.init(describing:)) ?? ""])
            exit(4)
        }
        emit("services_discovered")
        peripheral.discoverCharacteristics([valueID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard error == nil,
              let characteristic = service.characteristics?.first(where: { $0.uuid == valueID })
        else {
            emit("characteristics_failed", ["error": error.map(String.init(describing:)) ?? ""])
            exit(4)
        }
        self.characteristic = characteristic
        emit("characteristics_discovered")
        setStatus("MacPair: link live on \(targetName); pairing window…")
        // The firmware fires its SMP Security Request ~2 s into the link;
        // macOS then runs the pairing (the user confirms once if asked).
        // Keep reading every 2 s so the transcript spans the pairing and the
        // reads after it travel encrypted.
        peripheral.readValue(for: characteristic)
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            guard let characteristic = self.characteristic else { return }
            peripheral.readValue(for: characteristic)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                     error: Error?) {
        guard error == nil, let data = characteristic.value else {
            emit("read_failed", ["error": error.map(String.init(describing:)) ?? ""])
            return
        }
        let value = data.enumerated().reduce(UInt32(0)) {
            $0 | (UInt32($1.element) << UInt32($1.offset * 8))
        }
        reads += 1
        emit("read_result", ["value": value, "bytes": Array(data)])
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
