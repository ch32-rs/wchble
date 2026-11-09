import Foundation
import CoreBluetooth
import Darwin

let targetName = "wch585-p3"
let usage = """
Usage: central [--cycles COUNT] [--hold SECONDS] [--timeout SECONDS]
Connect-only P3 test (defaults: 1 cycle, 1-second hold, 20-second total timeout).
Matches the exact advertised local name wch585-p3, then locks its macOS UUID.
Never discovers services or performs GATT operations. Output is JSONL.
The total timeout includes scanning, all holds, and disconnect callbacks.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

struct Options {
    var cycles = 1
    var hold = 1.0
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
            case "--hold", "--timeout":
                guard let seconds = Double(value), seconds.isFinite, seconds > 0, seconds <= 3600 else {
                    throw CLIError("\(flag) must be finite and in (0, 3600]")
                }
                if flag == "--hold" { hold = seconds } else { timeout = seconds }
            default: throw CLIError("unknown option \(flag)")
            }
            index += 2
        }
        guard Double(cycles) * hold < timeout else {
            throw CLIError("--timeout must exceed cycles * hold, with time for scanning and disconnects")
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

final class ConnectOnly: NSObject, CBCentralManagerDelegate {
    let options: Options
    let started = monotonic()
    var manager: CBCentralManager!
    var watchdog: Timer?
    var signals: [DispatchSourceSignal] = []
    var target: CBPeripheral?
    var lockedID: UUID?
    var phase = "initializing"
    var connectedAt: Double?
    var cancelAt: Double?
    var heldSeconds = 0.0
    var completed = 0
    var pendingFailure: (Int32, String)?

    init(options: Options) { self.options = options; super.init() }

    func start() {
        emit("start", ["name": targetName, "cycles": options.cycles,
                       "hold_seconds": options.hold, "timeout_seconds": options.timeout,
                       "gatt_operations": 0])
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
            return
        }
        if phase == "holding", let connectedAt = connectedAt, now - connectedAt >= options.hold {
            heldSeconds = now - connectedAt
            phase = "cancelling"
            cancelAt = now
            emit("cancel_requested", ["cycle": completed + 1, "id": target!.identifier.uuidString,
                                      "held_seconds": heldSeconds])
            manager.cancelPeripheralConnection(target!)
        } else if phase == "cancelling", now - (cancelAt ?? now) >= 2 {
            fail(code: 5, reason: "disconnect_timeout")
        }
    }

    func scan() {
        phase = "scanning"
        target = nil
        connectedAt = nil
        cancelAt = nil
        manager.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        emit("scan_started", ["cycle": completed + 1,
                              "locked_id": lockedID?.uuidString as Any? ?? NSNull()])
    }

    func fail(code: Int32, reason: String) {
        guard phase != "done", phase != "cleanup" else { return }
        emit("error", ["reason": reason, "phase": phase])
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
                         "cycles_requested": options.cycles, "hold_seconds": options.hold,
                         "timeout_seconds": options.timeout, "elapsed_seconds": monotonic() - started,
                         "locked_id": lockedID?.uuidString as Any? ?? NSNull(), "gatt_operations": 0])
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
        emit("connecting", ["cycle": completed + 1, "id": peripheral.identifier.uuidString,
                            "local_name": targetName, "rssi": RSSI])
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        if phase == "cleanup" {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        guard phase == "connecting", peripheral.identifier == lockedID else {
            fail(code: 5, reason: "unexpected_connect_callback")
            return
        }
        connectedAt = monotonic()
        phase = "holding"
        emit("connected", ["cycle": completed + 1, "id": peripheral.identifier.uuidString])
        // Deliberately no CBPeripheral delegate, discovery, GATT, or pairing request.
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        emit("connect_failed", ["id": peripheral.identifier.uuidString,
                                "error": error?.localizedDescription as Any? ?? NSNull()])
        if phase == "cleanup", let failure = pendingFailure {
            exitNow(code: failure.0, reason: failure.1)
        } else {
            fail(code: 5, reason: "connect_failed")
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        let expected = phase == "cancelling"
        emit("disconnected", ["cycle": completed + 1, "id": peripheral.identifier.uuidString,
                              "expected": expected,
                              "error": error?.localizedDescription as Any? ?? NSNull()])
        if phase == "cleanup", let failure = pendingFailure {
            exitNow(code: failure.0, reason: failure.1)
            return
        }
        guard expected, peripheral.identifier == lockedID, error == nil,
              heldSeconds >= options.hold else {
            fail(code: 5, reason: "unexpected_disconnect")
            return
        }
        completed += 1
        emit("cycle_complete", ["cycle": completed, "id": peripheral.identifier.uuidString,
                                "held_seconds": heldSeconds])
        if completed == options.cycles {
            exitNow(code: 0, reason: "cycles_complete")
        } else {
            // A new attempt is allowed only after this disconnect callback.
            scan()
        }
    }
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--help"] || arguments == ["-h"] { print(usage); exit(0) }
    let session = ConnectOnly(options: try Options(arguments))
    session.start()
    withExtendedLifetime(session) { RunLoop.main.run() }
} catch {
    emit("error", ["message": String(describing: error)])
    exit(2)
}
