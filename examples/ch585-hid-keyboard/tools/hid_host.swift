import Foundation
import CoreBluetooth
import Darwin

// X4b HID harness client. Apple's Accessory Design Guidelines (§41.13) make
// CoreBluetooth filter the BLE HID service out of `discoverServices`, so a
// macOS app can never read 0x1812 or its reports (verified on hardware: the
// HID service is absent even when requested by UUID). Byte-level HOGP details
// are covered by tests/hid-host; this client instead verifies the exact HID
// input report cycle through the diagnostic mirror characteristic in the
// vendor service, on a link whose attributes require LE Secure Connections.
// JSONL output, one pass, no retries.
let targetName = "wch585-hid"
let vendorServiceID = CBUUID(string: "00001A00-B0CD-11EC-871F-D45DDF138840")
let bondControlID = CBUUID(string: "00001A01-B0CD-11EC-871F-D45DDF138840")
let mirrorID = CBUUID(string: "00001A02-B0CD-11EC-871F-D45DDF138840")

/// 'a' down, release, 'b', release, 'c', release, 'd', release.
let expectedCycle: [Data] = [
    Data([0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
]

let usage = """
Usage: hid_host [--timeout SECONDS] [--hold SECONDS]
X4b HID harness client (defaults: 30 s timeout, 0.5 s hold). Connects by the
exact advertised name, discovers the vendor service (Apple filters 0x1812 from
CoreBluetooth), reads and subscribes to the mirror characteristic, and verifies
the exact 8-report HID key cycle on an encrypted link. When macOS refuses
programmatic pairing (unsigned tools are checked in with fProgrammaticPairing
0), the protected subscription is refused and the client reports the security
gate instead. No retries. Output is JSONL.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct Options {
    var timeout = 30.0
    var hold = 0.5
    init(_ arguments: [String]) throws {
        var index = 0
        var seen = Set<String>()
        while index < arguments.count {
            let flag = arguments[index]
            guard seen.insert(flag).inserted else { throw CLIError("duplicate option \(flag)") }
            guard index + 1 < arguments.count else { throw CLIError("missing value for \(flag)") }
            let value = arguments[index + 1]
            switch flag {
            case "--timeout":
                guard let seconds = Double(value), seconds.isFinite, seconds > 0, seconds <= 3600 else {
                    throw CLIError("--timeout must be finite and in (0, 3600]")
                }
                timeout = seconds
            case "--hold":
                guard let seconds = Double(value), seconds.isFinite, seconds >= 0, seconds <= 60 else {
                    throw CLIError("--hold must be finite and in [0, 60]")
                }
                hold = seconds
            default: throw CLIError("unknown option \(flag)")
            }
            index += 2
        }
    }
}

func monotonic() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000 }

func emit(_ event: String, _ fields: [String: Any] = [:]) {
    var row = fields
    row["event"] = event
    row["monotonic_seconds"] = monotonic()
    do {
        let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    } catch {
        FileHandle.standardError.write(Data("JSON encoding failed: \(error)\n".utf8))
        exit(2)
    }
}

final class HidTest: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    let options: Options
    let started = monotonic()
    var manager: CBCentralManager!
    var watchdog: Timer?
    var signals: [DispatchSourceSignal] = []
    var target: CBPeripheral?
    var lockedID: UUID?
    var phase = "initializing"
    var cancelAt: Double?
    var pendingFailure: (Int32, String)?

    var vendorService: CBService?
    var bondControl: CBCharacteristic?
    var mirror: CBCharacteristic?

    var reads = 0
    var notifications = 0
    var values: [Data] = []
    var hidServiceVisible = false
    var securityGate: (code: Int, message: String)?

    init(options: Options) { self.options = options; super.init() }

    func step(_ event: String, _ fields: [String: Any] = [:]) {
        var row = fields
        row["id"] = target?.identifier.uuidString as Any? ?? NSNull()
        emit(event, row)
    }

    func start() {
        emit("start", ["name": targetName, "timeout_seconds": options.timeout,
                       "hold_seconds": options.hold])
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.fail(code: Int32(128 + number), reason: "interrupted") }
            source.resume()
            signals.append(source)
        }
        watchdog = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in self?.tick() }
        manager = CBCentralManager(delegate: self, queue: nil,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: false])
    }

    func tick() {
        let now = monotonic()
        if phase == "cleanup" {
            if now - (cancelAt ?? now) >= 2 {
                let failure = pendingFailure ?? (5, "disconnect_cleanup_timeout")
                exitNow(code: failure.0, reason: failure.1)
            }
            return
        }
        guard phase != "done" else { return }
        if now - started >= options.timeout {
            fail(code: phase == "initializing" ? 3 : 4, reason: "timeout_\(phase)")
        } else if phase == "cancelling", now - (cancelAt ?? now) >= 2 {
            fail(code: 5, reason: "disconnect_timeout")
        }
    }

    func scan() {
        phase = "scanning"
        target = nil
        manager.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        emit("scan_started")
    }

    func fail(code: Int32 = 5, reason: String) {
        guard phase != "done", phase != "cleanup" else { return }
        step("error", ["reason": reason, "phase": phase])
        manager?.stopScan()
        if let target = target, target.state != .disconnected {
            pendingFailure = (code, reason)
            phase = "cleanup"
            cancelAt = monotonic()
            manager.cancelPeripheralConnection(target)
        } else {
            exitNow(code: code, reason: reason)
        }
    }

    func exitNow(code: Int32, reason: String) {
        phase = "done"
        watchdog?.invalidate()
        manager?.stopScan()
        var fields: [String: Any] = ["exit_code": code, "reason": reason,
                                     "elapsed_seconds": monotonic() - started,
                                     "reads": reads, "notifications": notifications,
                                     "reports": values.count,
                                     "hid_service_visible": hidServiceVisible,
                                     "security_gate": securityGate != nil]
        if let gate = securityGate {
            fields["gate_code"] = gate.code
            fields["gate_message"] = gate.message
        }
        emit("summary", fields)
        exit(code)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        emit("bluetooth_state", ["state": central.state.rawValue,
                                 "authorization": CBManager.authorization.rawValue])
        guard phase != "cleanup", phase != "done" else { return }
        switch central.state {
        case .poweredOn:
            if phase == "initializing" { scan() }
        case .unauthorized: fail(code: 3, reason: "bluetooth_unauthorized")
        case .poweredOff: fail(code: 3, reason: "bluetooth_powered_off")
        case .unsupported: fail(code: 3, reason: "bluetooth_unsupported")
        case .resetting:
            if phase != "initializing" { fail(code: 3, reason: "bluetooth_reset") }
        default: break
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard phase == "scanning",
              advertisementData[CBAdvertisementDataLocalNameKey] as? String == targetName,
              lockedID == nil || lockedID == peripheral.identifier else { return }
        lockedID = peripheral.identifier
        target = peripheral
        phase = "connecting"
        central.stopScan()
        step("connecting", ["local_name": targetName, "rssi": RSSI])
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        if phase == "cleanup" { central.cancelPeripheralConnection(peripheral); return }
        guard phase == "connecting", peripheral.identifier == lockedID else {
            fail(reason: "unexpected_connect_callback"); return
        }
        peripheral.delegate = self
        step("connected")
        phase = "holding"
        DispatchQueue.main.asyncAfter(deadline: .now() + options.hold) { [weak self] in
            guard let self = self, self.phase == "holding" else { return }
            self.step("hold_complete")
            self.phase = "services"
            peripheral.discoverServices(nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        emit("connect_failed", ["id": peripheral.identifier.uuidString,
                                "error": error?.localizedDescription as Any? ?? NSNull()])
        if phase == "cleanup", let failure = pendingFailure {
            exitNow(code: failure.0, reason: failure.1)
        } else {
            fail(reason: "connect_failed")
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        let expected = phase == "cancelling" && peripheral.identifier == lockedID
        emit("disconnected", ["id": peripheral.identifier.uuidString, "expected": expected,
                              "error": error?.localizedDescription as Any? ?? NSNull()])
        if phase == "cleanup", let failure = pendingFailure {
            exitNow(code: failure.0, reason: failure.1)
            return
        }
        guard expected, error == nil else { fail(reason: "unexpected_disconnect"); return }
        exitNow(code: 0, reason: securityGate == nil ? "hid_mirror_ok" : "hid_security_gate_ok")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        let services = peripheral.services ?? []
        vendorService = services.first { $0.uuid == vendorServiceID }
        hidServiceVisible = services.contains { $0.uuid == CBUUID(string: "1812") }
        let uuids = services.map { $0.uuid.uuidString }
        guard phase == "services", error == nil, vendorService != nil else {
            step("service_discovery_failed", ["count": services.count, "uuids": uuids,
                                              "error": error?.localizedDescription as Any? ?? NSNull()])
            fail(reason: "service_discovery_failed_or_unexpected"); return
        }
        step("services_discovered", ["services": services.count, "uuids": uuids,
                                     "hid_service_visible": hidServiceVisible])
        phase = "characteristics"
        peripheral.discoverCharacteristics(nil, for: vendorService!)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard error == nil, service.uuid == vendorServiceID, phase == "characteristics" else {
            fail(reason: "characteristic_discovery_failed_or_unexpected"); return
        }
        let chars = service.characteristics ?? []
        guard let control = chars.first(where: { $0.uuid == bondControlID }),
              let channel = chars.first(where: { $0.uuid == mirrorID }) else {
            fail(reason: "missing_vendor_characteristic"); return
        }
        guard chars.count == 2, channel.properties.contains(.read),
              channel.properties.contains(.notify), control.properties.contains(.write),
              !channel.isNotifying else {
            fail(reason: "vendor_characteristic_properties_invalid"); return
        }
        bondControl = control
        mirror = channel
        step("characteristics_discovered", ["count": chars.count])
        // An encrypted CCCD write is the most reliable CoreBluetooth pairing
        // trigger; the mirror read follows once the link is encrypted.
        phase = "subscribing"
        step("notify_requested", ["characteristic": "mirror", "enabled": true])
        peripheral.setNotifyValue(true, for: channel)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        if let error = error, phase == "read_mirror" || phase == "subscribing" {
            // bluetoothd checks in unsigned tools with fProgrammaticPairing 0:
            // macOS never starts BLE pairing for this client and answers every
            // protected access with Insufficient Authentication after its ATT
            // timeout. That is the documented platform limitation; record the
            // gate and disconnect instead of retrying.
            let ns = error as NSError
            securityGate = (ns.code, ns.localizedDescription)
            step("security_gate", ["phase": phase, "domain": ns.domain, "code": ns.code,
                                   "message": ns.localizedDescription])
            cancel()
            return
        }
        switch phase {
        case "read_mirror":
            guard characteristic === mirror, let value = characteristic.value, value.count == 8 else {
                fail(reason: "mirror_read_wrong"); return
            }
            reads += 1
            step("read_result", ["field": "mirror", "bytes": Array(value)])
            phase = "reports"
        case "reports":
            guard characteristic === mirror, characteristic.isNotifying,
                  let value = characteristic.value else {
                fail(reason: "unexpected_report_notification"); return
            }
            notifications += 1
            guard values.count < expectedCycle.count else { return }
            guard value == expectedCycle[values.count] else {
                fail(reason: "report_\(values.count)_wrong_value"); return
            }
            values.append(value)
            step("notification", ["index": values.count - 1, "bytes": Array(value)])
            if values.count == expectedCycle.count {
                phase = "unsubscribing"
                target!.setNotifyValue(false, for: mirror!)
            }
        default:
            fail(reason: "unexpected_read_callback_\(phase)")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        if let error = error, phase == "subscribing" {
            let ns = error as NSError
            securityGate = (ns.code, ns.localizedDescription)
            step("security_gate", ["phase": phase, "domain": ns.domain, "code": ns.code,
                                   "message": ns.localizedDescription])
            cancel()
            return
        }
        switch phase {
        case "subscribing":
            guard changed === mirror, error == nil, changed.isNotifying else {
                fail(reason: "notify_state_failed_or_unexpected"); return
            }
            step("notify_state", ["enabled": true])
            phase = "read_mirror"
            step("read_requested", ["field": "mirror"])
            target!.readValue(for: mirror!)
        case "unsubscribing":
            guard changed === mirror, error == nil, !changed.isNotifying else {
                fail(reason: "unsubscribe_failed_or_unexpected"); return
            }
            step("notify_state", ["enabled": false])
            cancel()
        default:
            fail(reason: "unexpected_notification_state_callback_\(phase)")
        }
    }

    func cancel() {
        phase = "cancelling"
        cancelAt = monotonic()
        step("cancel_requested")
        manager.cancelPeripheralConnection(target!)
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] || arguments == ["-h"] { print(usage); exit(0) }
    let session = HidTest(options: try Options(arguments))
    session.start()
    withExtendedLifetime(session) { RunLoop.main.run() }
} catch {
    emit("error", ["message": String(describing: error)])
    exit(2)
}
