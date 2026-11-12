import Foundation
import CoreBluetooth

// One-shot setup helper: overwrite the vendor bond-control characteristic with
// `DEL!` so the firmware drops every stored bond. The control value is readable
// and writable on a plaintext link, which is exactly why it can repair the
// state where the Host still holds an LTK for a peer that has none (see
// local-docs/research/ch585-hid-results.md). One pass, JSONL, no retries.
let targetName = "wch585-hid"
let serviceID = CBUUID(string: "00001A00-B0CD-11EC-871F-D45DDF138840")
let controlID = CBUUID(string: "00001A01-B0CD-11EC-871F-D45DDF138840")

func monotonic() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }

func emit(_ event: String, _ fields: [String: Any] = [:]) {
    var row = fields
    row["event"] = event
    row["monotonic_seconds"] = monotonic()
    if let data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
}

final class Wipe: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var manager: CBCentralManager!
    var target: CBPeripheral?
    var done = false
    let started = monotonic()

    func start() {
        manager = CBCentralManager(delegate: self, queue: nil,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: false])
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            self?.finish(code: 4, reason: "timeout")
        }
    }

    func finish(code: Int32, reason: String) {
        guard !done else { return }
        done = true
        if let target = target, target.state != .disconnected {
            manager.cancelPeripheralConnection(target)
        }
        emit("summary", ["exit_code": code, "reason": reason,
                         "elapsed_seconds": monotonic() - started])
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { exit(code) }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if central.state != .resetting {
                finish(code: 3, reason: "bluetooth_unavailable")
            }
            return
        }
        central.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        emit("scan_started")
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard target == nil,
              advertisementData[CBAdvertisementDataLocalNameKey] as? String == targetName else { return }
        target = peripheral
        central.stopScan()
        emit("connecting", ["id": peripheral.identifier.uuidString])
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        emit("connected")
        peripheral.discoverServices([serviceID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        finish(code: 5, reason: "connect_failed")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        emit("disconnected")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == serviceID }) else {
            finish(code: 5, reason: "service_missing")
            return
        }
        peripheral.discoverCharacteristics([controlID], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard error == nil, let control = service.characteristics?.first(where: { $0.uuid == controlID }),
              control.properties.contains(.write) else {
            finish(code: 6, reason: "control_missing")
            return
        }
        emit("writing", ["bytes": Array("DEL!".utf8)])
        peripheral.writeValue(Data("DEL!".utf8), for: control, type: .withResponse)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        emit("write_ack", ["error": error?.localizedDescription as Any? ?? NSNull()])
        finish(code: error == nil ? 0 : 7, reason: error == nil ? "bond_delete_written" : "write_failed")
    }
}

let session = Wipe()
session.start()
withExtendedLifetime(session) { RunLoop.main.run() }
