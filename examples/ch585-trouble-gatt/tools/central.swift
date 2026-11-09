import Foundation
import CoreBluetooth
import Darwin

let targetName = "wch585-p4"
let serviceID = CBUUID(string: "00001000-b0cd-11ec-871f-d45ddf138840")
let characteristicID = CBUUID(string: "00001001-b0cd-11ec-871f-d45ddf138840")
let usage = """
Usage: central [--cycles COUNT] [--timeout SECONDS] [--name wch585-p4]
P4 u32LE GATT test (defaults: 1 cycle, 20-second total timeout).
Matches the exact advertised local name, then locks its macOS UUID.
Each cycle discovers services/characteristics, reads the initial value, writes
1...3 with read-back, enables notifications, writes 101...110 waiting for both
write acknowledgement and notification each time, disables notifications,
reads back 110, and explicitly disconnects. No retries. Output is JSONL.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct Options {
    var cycles = 1
    var timeout = 20.0

    init(_ arguments: [String]) throws {
        var index = 0
        var seen = Set<String>()
        while index < arguments.count {
            let flag = arguments[index]
            guard seen.insert(flag).inserted else { throw CLIError("duplicate option \(flag)") }
            guard index + 1 < arguments.count else { throw CLIError("missing value for \(flag)") }
            let value = arguments[index + 1]
            switch flag {
            case "--cycles":
                guard let count = Int(value), (1...1000).contains(count) else {
                    throw CLIError("--cycles must be in 1...1000")
                }
                cycles = count
            case "--timeout":
                guard let seconds = Double(value), seconds.isFinite, seconds > 0, seconds <= 3600 else {
                    throw CLIError("--timeout must be finite and in (0, 3600]")
                }
                timeout = seconds
            case "--name":
                guard value == targetName else { throw CLIError("--name must be \(targetName)") }
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

final class GATTTest: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    let options: Options
    let started = monotonic()
    var manager: CBCentralManager!
    var watchdog: Timer?
    var signals: [DispatchSourceSignal] = []
    var target: CBPeripheral?
    var characteristic: CBCharacteristic?
    var lockedID: UUID?
    var phase = "initializing"
    var cancelAt: Double?
    var completed = 0
    var pendingFailure: (Int32, String)?
    var expectedValue: UInt32 = 0
    var writeAcknowledged = false
    var notificationReceived = false
    var reads = 0
    var writes = 0
    var notifications = 0
    var subscriptions = 0

    init(options: Options) { self.options = options; super.init() }

    func step(_ event: String, _ fields: [String: Any] = [:]) {
        var row = fields
        row["cycle"] = completed + 1
        row["id"] = target?.identifier.uuidString as Any? ?? NSNull()
        emit(event, row)
    }

    func start() {
        emit("start", ["name": targetName, "cycles": options.cycles,
                       "timeout_seconds": options.timeout, "service": serviceID.uuidString.lowercased(),
                       "characteristic": characteristicID.uuidString.lowercased()])
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in
                self?.fail(code: Int32(128 + number), reason: "interrupted")
            }
            source.resume()
            signals.append(source)
        }
        watchdog = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            self?.tick()
        }
        manager = CBCentralManager(delegate: self, queue: nil,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: false])
    }

    func tick() {
        let now = monotonic()
        if phase == "cleanup" {
            if now - (cancelAt ?? now) >= 2 {
                emit("cleanup_timeout")
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
        characteristic = nil
        cancelAt = nil
        manager.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        emit("scan_started", ["cycle": completed + 1,
                              "locked_id": lockedID?.uuidString as Any? ?? NSNull()])
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
        emit("summary", ["exit_code": code, "reason": reason, "cycles_completed": completed,
                         "cycles_requested": options.cycles, "timeout_seconds": options.timeout,
                         "elapsed_seconds": monotonic() - started,
                         "locked_id": lockedID?.uuidString as Any? ?? NSNull(),
                         "reads": reads, "writes": writes, "notifications": notifications,
                         "subscriptions": subscriptions])
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
        if phase == "cleanup" {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        guard phase == "connecting", peripheral.identifier == lockedID else {
            fail(reason: "unexpected_connect_callback")
            return
        }
        peripheral.delegate = self
        phase = "services"
        step("connected")
        step("services_requested", ["service": serviceID.uuidString.lowercased()])
        peripheral.discoverServices([serviceID])
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
        emit("disconnected", ["cycle": completed + 1, "id": peripheral.identifier.uuidString,
                              "expected": expected,
                              "error": error?.localizedDescription as Any? ?? NSNull()])
        if phase == "cleanup", let failure = pendingFailure {
            exitNow(code: failure.0, reason: failure.1)
            return
        }
        guard expected, error == nil else {
            fail(reason: "unexpected_disconnect")
            return
        }
        step("cycle_complete")
        completed += 1
        if completed == options.cycles {
            exitNow(code: 0, reason: "cycles_complete")
        } else {
            scan()
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        let matches = peripheral.services?.filter { $0.uuid == serviceID } ?? []
        guard phase == "services", peripheral.identifier == lockedID,
              error == nil, matches.count == 1 else {
            fail(reason: "service_discovery_failed_or_unexpected")
            return
        }
        step("services_discovered", ["service": serviceID.uuidString.lowercased()])
        phase = "characteristics"
        step("characteristics_requested", ["characteristic": characteristicID.uuidString.lowercased()])
        peripheral.discoverCharacteristics([characteristicID], for: matches[0])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        let matches = service.characteristics?.filter { $0.uuid == characteristicID } ?? []
        guard phase == "characteristics", peripheral.identifier == lockedID,
              service.uuid == serviceID, error == nil, matches.count == 1 else {
            fail(reason: "characteristic_discovery_failed_or_unexpected")
            return
        }
        let found = matches[0]
        let readable = found.properties.contains(.read)
        let writable = found.properties.contains(.write)
        let notifiable = found.properties.contains(.notify)
        step("characteristics_discovered", ["characteristic": characteristicID.uuidString.lowercased(),
                                            "read": readable, "write": writable, "notify": notifiable])
        guard readable, writable, notifiable, !found.isNotifying else {
            fail(reason: "characteristic_properties_or_initial_subscription_invalid")
            return
        }
        characteristic = found
        read("initial")
    }

    func read(_ purpose: String) {
        phase = "read_\(purpose)"
        step("read_requested", ["purpose": purpose])
        target!.readValue(for: characteristic!)
    }

    func write(_ value: UInt32, notifying: Bool) {
        expectedValue = value
        writeAcknowledged = false
        notificationReceived = false
        phase = notifying ? "write_notify" : "write_readback"
        let data = Data((0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
        step("write_requested", ["value": value, "mode": notifying ? "notify" : "readback",
                                 "bytes": Array(data)])
        target!.writeValue(data, for: characteristic!, type: .withResponse)
    }

    func setNotify(_ enabled: Bool) {
        phase = enabled ? "notify_on" : "notify_off"
        step("notify_requested", ["enabled": enabled])
        target!.setNotifyValue(enabled, for: characteristic!)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        let enabling = phase == "notify_on"
        guard (enabling || phase == "notify_off"), peripheral.identifier == lockedID,
              changed === characteristic, error == nil, changed.isNotifying == enabling else {
            fail(reason: "notification_state_failed_or_unexpected")
            return
        }
        subscriptions += 1
        step("notify_state", ["enabled": changed.isNotifying])
        if enabling { write(101, notifying: true) } else { read("final") }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard (phase == "write_notify" || phase == "write_readback"),
              peripheral.identifier == lockedID, changed === characteristic,
              error == nil, !writeAcknowledged else {
            fail(reason: "write_failed_or_unexpected")
            return
        }
        writeAcknowledged = true
        writes += 1
        step("write_ack", ["value": expectedValue])
        if phase == "write_readback" { read("verify") } else { advanceNotificationWrite() }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard peripheral.identifier == lockedID, changed === characteristic,
              error == nil, let data = changed.value, data.count == 4 else {
            fail(reason: "value_failed_or_not_u32le")
            return
        }
        let value = data.enumerated().reduce(UInt32(0)) { $0 | (UInt32($1.element) << ($1.offset * 8)) }
        if phase == "write_notify" {
            // No read request is outstanding while notifications are enabled.
            guard changed.isNotifying, !notificationReceived, value == expectedValue else {
                fail(reason: "notification_duplicate_or_wrong_value")
                return
            }
            notificationReceived = true
            notifications += 1
            step("notification", ["value": value, "bytes": Array(data)])
            advanceNotificationWrite()
        } else if ["read_initial", "read_verify", "read_final"].contains(phase) {
            guard !changed.isNotifying else { fail(reason: "read_while_notifying"); return }
            let purpose = String(phase.dropFirst(5))
            step("read_result", ["purpose": purpose, "value": value, "bytes": Array(data)])
            guard purpose == "initial" || value == (purpose == "final" ? 110 : expectedValue) else {
                fail(reason: "readback_wrong_value")
                return
            }
            reads += 1
            if purpose == "initial" {
                write(1, notifying: false)
            } else if purpose == "verify" {
                if expectedValue < 3 { write(expectedValue + 1, notifying: false) } else { setNotify(true) }
            } else {
                phase = "cancelling"
                cancelAt = monotonic()
                step("cancel_requested")
                manager.cancelPeripheralConnection(peripheral)
            }
        } else {
            fail(reason: "unexpected_value_callback")
        }
    }

    func advanceNotificationWrite() {
        guard writeAcknowledged, notificationReceived else { return }
        if expectedValue < 110 { write(expectedValue + 1, notifying: true) } else { setNotify(false) }
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] || arguments == ["-h"] { print(usage); exit(0) }
    let session = GATTTest(options: try Options(arguments))
    session.start()
    withExtendedLifetime(session) { RunLoop.main.run() }
} catch {
    emit("error", ["message": String(describing: error)])
    exit(2)
}
