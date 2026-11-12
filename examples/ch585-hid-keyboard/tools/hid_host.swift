import Foundation
import CoreBluetooth
import Darwin

// X4b HID acceptance client: byte-level HOGP assertions over CoreBluetooth.
// A single pass: discover 0x1812, read HID Information / Report Map / Protocol
// Mode, check the 0x2908 Report Reference descriptors, subscribe to the input
// report and verify the fixed key cycle, write the LED output report and the
// HID Control Point, switch to boot protocol and back. JSONL output.
let targetName = "wch585-hid"
let hidServiceID = CBUUID(string: "1812")
let hidInfoID = CBUUID(string: "2a4a")
let reportMapID = CBUUID(string: "2a4b")
let controlPointID = CBUUID(string: "2a4c")
let reportID = CBUUID(string: "2a4d")
let protocolModeID = CBUUID(string: "2a4e")
let bootInputID = CBUUID(string: "2a22")
let bootOutputID = CBUUID(string: "2a32")
let reportReferenceID = CBUUID(string: "2908")

let expectedInfo = Data([0x11, 0x01, 0x00, 0x01])
let expectedMap = Data([
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25,
    0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
    0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
    0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
    0x81, 0x00, 0xc0,
])
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
let ledValue = Data([0x07])

let usage = """
Usage: hid_host [--timeout SECONDS] [--hold SECONDS] [--discover-only]
HOGP keyboard acceptance client (defaults: 30 s timeout, 6 s hold).
Holds after connect so the peripheral's delayed Security Request can finish
pairing, then reads HID Information/Report Map/Protocol Mode, checks the
0x2908 Report Reference descriptors, verifies the fixed 8-report key cycle,
writes the LED/Control Point values and exercises boot protocol. --discover-only
stops after the descriptor and value reads and disconnects. No retries. Output
is JSONL.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct Options {
    var timeout = 30.0
    var hold = 6.0
    var discoverOnly = false
    init(_ arguments: [String]) throws {
        var index = 0
        var seen = Set<String>()
        while index < arguments.count {
            let flag = arguments[index]
            guard seen.insert(flag).inserted else { throw CLIError("duplicate option \(flag)") }
            if flag == "--discover-only" {
                discoverOnly = true
                index += 1
                continue
            }
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

    var hidService: CBService?
    var hidInfo: CBCharacteristic?
    var reportMap: CBCharacteristic?
    var controlPoint: CBCharacteristic?
    var protocolMode: CBCharacteristic?
    var inputReport: CBCharacteristic?
    var outputReport: CBCharacteristic?
    var bootInput: CBCharacteristic?
    var bootOutput: CBCharacteristic?
    var inputReference: CBDescriptor?
    var outputReference: CBDescriptor?

    var referenceReads = 0
    var descriptorsPending = 0
    var reads = 0
    var writes = 0
    var notifications = 0
    var reportValues: [Data] = []
    var bootValues: [Data] = []
    var startedReportCount = 0
    var unsubscribePending = 0

    init(options: Options) { self.options = options; super.init() }

    func step(_ event: String, _ fields: [String: Any] = [:]) {
        var row = fields
        row["id"] = target?.identifier.uuidString as Any? ?? NSNull()
        emit(event, row)
    }

    func start() {
        emit("start", ["name": targetName, "timeout_seconds": options.timeout,
                       "hold_seconds": options.hold, "discover_only": options.discoverOnly])
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
        emit("summary", ["exit_code": code, "reason": reason,
                         "elapsed_seconds": monotonic() - started,
                         "reads": reads, "writes": writes, "notifications": notifications,
                         "reports": startedReportCount, "boot_reports": bootValues.count,
                         "discover_only": options.discoverOnly])
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
        // The peripheral sends a Security Request two seconds after connect.
        // Holding lets the system pairing dialog complete before the first
        // encrypted read, instead of racing it with service discovery.
        phase = "holding"
        DispatchQueue.main.asyncAfter(deadline: .now() + options.hold) { [weak self] in
            guard let self = self, self.phase == "holding" else { return }
            self.step("hold_complete")
            self.phase = "services"
            peripheral.discoverServices([hidServiceID])
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
        let reason = options.discoverOnly ? "hid_discovery_ok" : "hid_reports_ok"
        exitNow(code: 0, reason: reason)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        let services = peripheral.services ?? []
        hidService = services.first { $0.uuid == hidServiceID }
        guard phase == "services", error == nil, services.count == 1, hidService != nil else {
            fail(reason: "service_discovery_failed_or_unexpected"); return
        }
        step("services_discovered", ["services": services.count])
        phase = "characteristics"
        peripheral.discoverCharacteristics(nil, for: hidService!)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        guard error == nil, service.uuid == hidServiceID, phase == "characteristics" else {
            fail(reason: "characteristic_discovery_failed_or_unexpected"); return
        }
        let chars = service.characteristics ?? []
        guard chars.count == 9 else {
            fail(reason: "hid_characteristic_count_\(chars.count)"); return
        }
        func find(_ uuid: CBUUID) -> [CBCharacteristic] {
            chars.filter { $0.uuid == uuid }
        }
        guard let info = find(hidInfoID).first, let map = find(reportMapID).first,
              let point = find(controlPointID).first, let mode = find(protocolModeID).first,
              let bootIn = find(bootInputID).first, let bootOut = find(bootOutputID).first else {
            fail(reason: "missing_hid_characteristic"); return
        }
        let reportChars = find(reportID)
        guard reportChars.count == 2 else {
            fail(reason: "report_characteristic_count_\(reportChars.count)"); return
        }
        guard let input = reportChars.first(where: { $0.properties.contains(.notify) }),
              let output = reportChars.first(where: { $0.properties.contains(.write) }),
              input !== output else {
            fail(reason: "report_characteristics_invalid"); return
        }
        guard input.properties.contains(.read), output.properties.contains(.writeWithoutResponse),
              bootIn.properties.contains(.notify), bootOut.properties.contains(.write),
              !input.isNotifying, !bootIn.isNotifying else {
            fail(reason: "hid_properties_invalid"); return
        }
        hidInfo = info
        reportMap = map
        controlPoint = point
        protocolMode = mode
        inputReport = input
        outputReport = output
        bootInput = bootIn
        bootOutput = bootOut
        step("characteristics_discovered", ["count": chars.count, "reports": reportChars.count])
        phase = "descriptors"
        descriptorsPending = 2
        peripheral.discoverDescriptors(for: input)
        peripheral.discoverDescriptors(for: output)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverDescriptorsFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase == "descriptors", error == nil else {
            fail(reason: "descriptor_discovery_failed"); return
        }
        let references = (characteristic.descriptors ?? []).filter { $0.uuid == reportReferenceID }
        guard references.count == 1 else {
            fail(reason: "report_reference_invalid"); return
        }
        if characteristic === inputReport {
            inputReference = references[0]
        } else if characteristic === outputReport {
            outputReference = references[0]
        } else {
            fail(reason: "unexpected_descriptor_owner"); return
        }
        descriptorsPending -= 1
        guard descriptorsPending == 0, let input = inputReference, let output = outputReference else {
            return
        }
        phase = "descriptor_reads"
        peripheral.readValue(for: input)
        peripheral.readValue(for: output)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor descriptor: CBDescriptor,
                    error: Error?) {
        guard phase != "cleanup", phase == "descriptor_reads", error == nil,
              let value = descriptor.value as? Data else {
            fail(reason: "descriptor_read_failed"); return
        }
        if descriptor === inputReference {
            guard value == Data([0x00, 0x01]) else {
                fail(reason: "input_report_reference_wrong"); return
            }
        } else if descriptor === outputReference {
            guard value == Data([0x00, 0x02]) else {
                fail(reason: "output_report_reference_wrong"); return
            }
        } else {
            fail(reason: "unexpected_descriptor_callback"); return
        }
        reads += 1
        referenceReads += 1
        step("descriptor_read", ["bytes": Array(value),
                                 "owner": descriptor === inputReference ? "input" : "output"])
        if referenceReads == 2 {
            phase = "reads"
            readCharacteristic(hidInfo!, name: "hid_info")
        }
    }

    func readCharacteristic(_ characteristic: CBCharacteristic, name: String) {
        phase = "read_\(name)"
        step("read_requested", ["field": name])
        target!.readValue(for: characteristic)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done", error == nil else {
            fail(reason: "value_failed_or_unexpected"); return
        }
        switch phase {
        case "read_hid_info":
            guard characteristic === hidInfo, characteristic.value == expectedInfo else {
                fail(reason: "hid_info_wrong_value"); return
            }
            reads += 1
            step("read_result", ["field": "hid_info", "bytes": Array(expectedInfo)])
            readCharacteristic(reportMap!, name: "report_map")
        case "read_report_map":
            guard characteristic === reportMap, characteristic.value == expectedMap else {
                fail(reason: "report_map_wrong_value"); return
            }
            reads += 1
            step("read_result", ["field": "report_map", "bytes": expectedMap.count])
            readCharacteristic(protocolMode!, name: "protocol_mode")
        case "read_protocol_mode":
            guard characteristic === protocolMode, characteristic.value == Data([0x01]) else {
                fail(reason: "protocol_mode_wrong_value"); return
            }
            reads += 1
            step("read_result", ["field": "protocol_mode", "bytes": [0x01]])
            if options.discoverOnly {
                cancel()
            } else {
                phase = "subscribing"
                step("notify_requested", ["characteristic": "input_report", "enabled": true])
                target!.setNotifyValue(true, for: inputReport!)
            }
        case "reports":
            guard characteristic === inputReport, characteristic.isNotifying,
                  let value = characteristic.value else {
                fail(reason: "unexpected_report_notification"); return
            }
            notifications += 1
            guard startedReportCount < expectedCycle.count else { return }
            guard value == expectedCycle[startedReportCount] else {
                fail(reason: "report_\(startedReportCount)_wrong_value"); return
            }
            reportValues.append(value)
            step("notification", ["index": startedReportCount, "bytes": Array(value)])
            startedReportCount += 1
            if startedReportCount == expectedCycle.count {
                guard reportValues == expectedCycle else {
                    fail(reason: "report_cycle_wrong"); return
                }
                phase = "led"
                step("write_requested", ["field": "led", "bytes": Array(ledValue)])
                target!.writeValue(ledValue, for: outputReport!, type: .withResponse)
            }
        case "boot_read_mode":
            guard characteristic === protocolMode, characteristic.value == Data([0x00]) else {
                fail(reason: "boot_protocol_mode_not_applied"); return
            }
            reads += 1
            step("read_result", ["field": "protocol_mode", "bytes": [0x00]])
            phase = "boot_subscribing"
            step("notify_requested", ["characteristic": "boot_input", "enabled": true])
            target!.setNotifyValue(true, for: bootInput!)
        case "boot_reports":
            guard characteristic === bootInput, characteristic.isNotifying,
                  let value = characteristic.value else {
                fail(reason: "unexpected_boot_notification"); return
            }
            notifications += 1
            guard bootValues.count < 2 else { return }
            let index = bootValues.count
            guard value == expectedCycle[index] else {
                fail(reason: "boot_report_\(index)_wrong_value"); return
            }
            bootValues.append(value)
            step("boot_notification", ["index": index, "bytes": Array(value)])
            if bootValues.count == 2 {
                phase = "restore_mode"
                step("write_requested", ["field": "protocol_mode", "bytes": [0x01]])
                target!.writeValue(Data([0x01]), for: protocolMode!, type: .withoutResponse)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                    guard let self = self, self.phase == "restore_mode" else { return }
                    self.readCharacteristic(self.protocolMode!, name: "restored_protocol_mode")
                }
            }
        case "read_restored_protocol_mode":
            guard characteristic === protocolMode, characteristic.value == Data([0x01]) else {
                fail(reason: "restored_protocol_mode_wrong"); return
            }
            reads += 1
            step("read_result", ["field": "protocol_mode", "bytes": [0x01]])
            phase = "unsubscribing"
            unsubscribePending = 2
            target!.setNotifyValue(false, for: inputReport!)
            target!.setNotifyValue(false, for: bootInput!)
        default:
            fail(reason: "unexpected_read_callback_\(phase)")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase != "done" else { return }
        switch phase {
        case "subscribing":
            guard changed === inputReport, error == nil, changed.isNotifying else {
                fail(reason: "notify_state_failed_or_unexpected"); return
            }
            step("notify_state", ["enabled": true])
            phase = "reports"
        case "boot_subscribing":
            guard changed === bootInput, error == nil, changed.isNotifying else {
                fail(reason: "boot_notify_state_failed"); return
            }
            step("notify_state", ["enabled": true, "characteristic": "boot_input"])
            phase = "boot_reports"
        case "unsubscribing":
            guard error == nil, !changed.isNotifying else {
                fail(reason: "unsubscribe_failed_or_unexpected"); return
            }
            unsubscribePending -= 1
            if unsubscribePending == 0 {
                cancel()
            }
        default:
            fail(reason: "unexpected_notification_state_callback_\(phase)")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor changed: CBCharacteristic,
                    error: Error?) {
        guard phase != "cleanup", phase == "led", changed === outputReport, error == nil else {
            fail(reason: "led_write_failed_or_unexpected"); return
        }
        writes += 1
        step("write_ack", ["field": "led", "bytes": Array(ledValue)])
        // HID Control Point: Suspend, then Exit Suspend (no responses).
        step("write_sent", ["field": "control_point", "bytes": [0x00]])
        target!.writeValue(Data([0x00]), for: controlPoint!, type: .withoutResponse)
        step("write_sent", ["field": "control_point", "bytes": [0x01]])
        target!.writeValue(Data([0x01]), for: controlPoint!, type: .withoutResponse)
        // Boot protocol: write 0, read back, subscribe boot input.
        phase = "boot_mode_write"
        step("write_sent", ["field": "protocol_mode", "bytes": [0x00]])
        target!.writeValue(Data([0x00]), for: protocolMode!, type: .withoutResponse)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            guard let self = self, self.phase == "boot_mode_write" else { return }
            self.readCharacteristic(self.protocolMode!, name: "boot_protocol_mode")
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
