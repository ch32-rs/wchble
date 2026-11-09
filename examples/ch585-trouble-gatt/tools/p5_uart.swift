import Foundation
import CoreBluetooth
import Darwin

// P5 manual client: Device Information reads plus a write/notify UART echo.
let targetName = "wch585-p4"
let infoID = CBUUID(string: "180a")
let manufacturerID = CBUUID(string: "2a29")
let modelID = CBUUID(string: "2a24")
let revisionID = CBUUID(string: "2a26")
let uartServiceID = CBUUID(string: "6e400001-b5a3-f393-e0a9-e50e24dcca9e")
let uartRXID = CBUUID(string: "6e400002-b5a3-f393-e0a9-e50e24dcca9e")
let uartTXID = CBUUID(string: "6e400003-b5a3-f393-e0a9-e50e24dcca9e")
let expectedManufacturer = Data("wchble".utf8)
let expectedModel = Data("ch585-trouble-gatt".utf8)
let expectedRevision = Data("p5-0.1".utf8)
let usage = """
Usage: p5_uart [--cycles COUNT] [--timeout SECONDS]
P5 Device Information + Nordic UART echo test (defaults: 1 cycle, 20 s).
Each cycle reads manufacturer/model/revision, subscribes to UART TX, writes
"p5-<cycle>" to RX, requires exactly one matching echo notification, then
disables notifications and disconnects. No retries. Output is JSONL.
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
                guard let count = Int(value), (1...100).contains(count) else {
                    throw CLIError("--cycles must be in 1...100")
                }
                cycles = count
            case "--timeout":
                guard let seconds = Double(value), seconds.isFinite, seconds > 0, seconds <= 3600 else {
                    throw CLIError("--timeout must be finite and in (0, 3600]")
                }
                timeout = seconds
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

final class P5Test: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    let options: Options
    let started = monotonic()
    var manager: CBCentralManager!
    var watchdog: Timer?
    var signals: [DispatchSourceSignal] = []
    var target: CBPeripheral?
    var lockedID: UUID?
    var phase = "initializing"
    var cancelAt: Double?
    var completed = 0
    var pendingFailure: (Int32, String)?
    var infoService: CBService?
    var uartService: CBService?
    var uartRX: CBCharacteristic?
    var uartTX: CBCharacteristic?
    var expecting = Data()
    var writeAcknowledged = false
    var notificationReceived = false
    var infoReadsDone = false
    var notifyStarted = false
    var reads = 0
    var writes = 0
    var notifications = 0

    init(options: Options) { self.options = options; super.init() }

    func step(_ event: String, _ fields: [String: Any] = [:]) {
        var row = fields
        row["cycle"] = completed + 1
        row["id"] = target?.identifier.uuidString as Any? ?? NSNull()
        emit(event, row)
    }

    func start() {
        emit("start", ["name": targetName, "cycles": options.cycles,
                       "timeout_seconds": options.timeout])
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
        infoService = nil
        uartService = nil
        uartRX = nil
        uartTX = nil
        infoReadsDone = false
        notifyStarted = false
        writeAcknowledged = false
        notificationReceived = false
        manager.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        emit("scan_started", ["cycle": completed + 1])
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
                         "cycles_requested": options.cycles, "elapsed_seconds": monotonic() - started,
                         "reads": reads, "writes": writes, "notifications": notifications])
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
        phase = "services"
        step("connected")
        peripheral.discoverServices([infoID, uartServiceID])
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
        guard expected, error == nil else { fail(reason: "unexpected_disconnect"); return }
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
        let services = peripheral.services ?? []
        infoService = services.first { $0.uuid == infoID }
        uartService = services.first { $0.uuid == uartServiceID }
        guard phase == "services", error == nil,
              infoService != nil, uartService != nil, services.count == 2 else {
            fail(reason: "service_discovery_failed_or_unexpected"); return
        }
        step("services_discovered")
        phase = "characteristics"
        peripheral.discoverCharacteristics([manufacturerID, modelID, revisionID], for: infoService!)
        peripheral.discoverCharacteristics([uartRXID, uartTXID], for: uartService!)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard error == nil else {
            fail(reason: "characteristic_discovery_failed_or_unexpected"); return
        }
        if service.uuid == infoID {
            guard phase == "characteristics" else {
                fail(reason: "duplicate_device_information_discovery"); return
            }
            let chars = service.characteristics ?? []
            guard chars.count == 3 else { fail(reason: "dis_info_characteristics_invalid"); return }
            read(manufacturerID)
        } else if service.uuid == uartServiceID {
            // This callback can arrive while the Device Information reads are
            // still in flight; only duplicate discovery is out of order.
            guard uartRX == nil, uartTX == nil else {
                fail(reason: "duplicate_uart_discovery"); return
            }
            let chars = service.characteristics ?? []
            uartRX = chars.first { $0.uuid == uartRXID }
            uartTX = chars.first { $0.uuid == uartTXID }
            guard chars.count == 2, let rx = uartRX, let tx = uartTX,
                  rx.properties.contains(.write), tx.properties.contains(.notify),
                  !tx.isNotifying else {
                fail(reason: "uart_characteristics_invalid"); return
            }
            step("uart_characteristics", ["rx_write": true, "tx_notify": true])
            if infoReadsDone { startNotify() }
        }
    }

    func startNotify() {
        guard !notifyStarted else { return }
        notifyStarted = true
        phase = "notify_on"
        step("notify_requested", ["enabled": true])
        target!.setNotifyValue(true, for: uartTX!)
    }

    func characteristic(_ uuid: CBUUID) -> CBCharacteristic? {
        guard let service = (uuid == uartRXID || uuid == uartTXID) ? uartService : infoService else {
            return nil
        }
        return service.characteristics?.first { $0.uuid == uuid }
    }

    func read(_ uuid: CBUUID) {
        guard let found = characteristic(uuid) else { fail(reason: "missing_read_characteristic"); return }
        let name = uuid == manufacturerID ? "manufacturer" : uuid == modelID ? "model" : "revision"
        phase = "read_\(name)"
        step("read_requested", ["field": name])
        target!.readValue(for: found)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard peripheral.identifier == lockedID, error == nil else {
            fail(reason: "value_failed_or_unexpected"); return
        }
        if let uuid = characteristicUUID(changed) {
            let expected: Data
            let next: CBUUID?
            switch (uuid, phase) {
            case (manufacturerID, "read_manufacturer"):
                expected = expectedManufacturer; next = modelID
            case (modelID, "read_model"):
                expected = expectedModel; next = revisionID
            case (revisionID, "read_revision"):
                expected = expectedRevision; next = nil
            default:
                fail(reason: "unexpected_read_callback"); return
            }
            guard changed.value == expected else { fail(reason: "device_information_wrong_value"); return }
            reads += 1
            step("read_result", ["field": uuid == manufacturerID ? "manufacturer" :
                                  uuid == modelID ? "model" : "revision",
                                  "bytes": Array(expected)])
            if let next = next {
                read(next)
            } else {
                infoReadsDone = true
                if uartTX != nil {
                    startNotify()
                } else {
                    phase = "info_done"
                }
            }
            return
        }
        guard phase == "write_notify", changed === uartTX, changed.isNotifying,
              !notificationReceived, changed.value == expecting else {
            fail(reason: "notification_duplicate_or_wrong_value"); return
        }
        notificationReceived = true
        notifications += 1
        step("notification", ["bytes": Array(expecting)])
        advance()
    }

    func characteristicUUID(_ changed: CBCharacteristic) -> CBUUID? {
        if let service = infoService, service.characteristics?.contains(where: { $0 === changed }) == true {
            return changed.uuid
        }
        return nil
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        if phase == "notify_on" {
            guard changed === uartTX, error == nil, changed.isNotifying else {
                fail(reason: "notification_state_failed_or_unexpected"); return
            }
            step("notify_state", ["enabled": true])
            expecting = Data("p5-\(completed + 1)".utf8)
            writeAcknowledged = false
            notificationReceived = false
            phase = "write_notify"
            step("write_requested", ["bytes": Array(expecting)])
            target!.writeValue(expecting, for: uartRX!, type: .withResponse)
        } else if phase == "notify_off" {
            guard changed === uartTX, error == nil, !changed.isNotifying else {
                fail(reason: "unsubscribe_failed_or_unexpected"); return
            }
            step("notify_state", ["enabled": false])
            phase = "cancelling"
            cancelAt = monotonic()
            step("cancel_requested")
            manager.cancelPeripheralConnection(peripheral)
        } else {
            fail(reason: "unexpected_notification_state_callback")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard phase == "write_notify", changed === uartRX,
              error == nil, !writeAcknowledged else {
            fail(reason: "write_failed_or_unexpected"); return
        }
        writeAcknowledged = true
        writes += 1
        step("write_ack")
        advance()
    }

    func advance() {
        guard writeAcknowledged, notificationReceived else { return }
        phase = "notify_off"
        step("notify_requested", ["enabled": false])
        target!.setNotifyValue(false, for: uartTX!)
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] || arguments == ["-h"] { print(usage); exit(0) }
    let session = P5Test(options: try Options(arguments))
    session.start()
    withExtendedLifetime(session) { RunLoop.main.run() }
} catch {
    emit("error", ["message": String(describing: error)])
    exit(2)
}
