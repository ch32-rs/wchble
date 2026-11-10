#!/usr/bin/env swift
// Controlled legacy advertisement source for the CH585 passive Observer test.
// This is a test instrument: CoreBluetooth does not expose the advertising
// interval or guarantee which AD structures land in ADV_IND.
import CoreBluetooth
import Foundation

func emit(_ event: String, _ fields: [String: Any] = [:]) {
    var object = fields
    object["event"] = event
    object["elapsed_s"] = Date().timeIntervalSince(started)
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
          var line = String(data: data, encoding: .utf8) else { return }
    line += "\n"
    FileHandle.standardOutput.write(line.data(using: .utf8)!)
}

func fail(_ message: String, code: Int32) -> Never {
    emit("error", ["message": message])
    exit(code)
}

let started = Date()

final class Advertiser: NSObject, CBPeripheralManagerDelegate {
    private let name: String
    private let manufacturer: Data
    private let seconds: TimeInterval
    private var manager: CBPeripheralManager!
    private var advertising = false
    private var finished = false
    private var signals: [DispatchSourceSignal] = []

    init(name: String, manufacturer: Data, seconds: TimeInterval) {
        self.name = name
        self.manufacturer = manufacturer
        self.seconds = seconds
        super.init()
        emit("start", ["name": name, "manufacturer": manufacturer.map { String(format: "%02x", $0) }.joined(),
                       "seconds": seconds])
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        for sig in [SIGINT, SIGTERM] {
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { [weak self] in self?.finish() }
            source.resume()
            signals.append(source)
        }
        manager = CBPeripheralManager(delegate: self, queue: nil)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, !self.advertising else { return }
            fail("Bluetooth did not become ready within 5 s", code: 2)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in
            self?.finish()
        }
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            guard !advertising else { return }
            advertising = true
            var payload: [String: Any] = [CBAdvertisementDataLocalNameKey: name]
            if !manufacturer.isEmpty {
                payload[CBAdvertisementDataManufacturerDataKey] = manufacturer
            }
            peripheral.startAdvertising(payload)
        case .unknown, .resetting:
            break
        default:
            fail("Bluetooth unavailable: state=\(peripheral.state.rawValue)", code: 2)
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            fail("startAdvertising failed: \(error)", code: 3)
        }
        emit("advertising", ["name": name,
                             "manufacturer": manufacturer.map { String(format: "%02x", $0) }.joined()])
    }

    func finish() {
        if finished { return }
        finished = true
        manager.stopAdvertising()
        emit("stopped")
        exit(0)
    }
}

func parseHex(_ text: String) -> Data? {
    let clean = text.replacingOccurrences(of: " ", with: "")
        .replacingOccurrences(of: ":", with: "")
    guard clean.count % 2 == 0 else { return nil }
    var bytes = [UInt8]()
    var index = clean.startIndex
    while index < clean.endIndex {
        let next = clean.index(index, offsetBy: 2)
        guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
        bytes.append(byte)
        index = next
    }
    return Data(bytes)
}

var name = "wch585-obs-src"
var manufacturer = Data([0xff, 0xff, 0x4f, 0x31, 0x00, 0x01])
var seconds: Double? = nil

var args = Array(CommandLine.arguments.dropFirst())
while !args.isEmpty {
    let arg = args.removeFirst()
    switch arg {
    case "--seconds":
        guard !args.isEmpty, let value = Double(args.removeFirst()) else { fail("--seconds needs a number", code: 2) }
        seconds = value
    case "--name":
        guard !args.isEmpty else { fail("--name needs a value", code: 2) }
        name = args.removeFirst()
    case "--manufacturer":
        guard !args.isEmpty, let value = parseHex(args.removeFirst()) else {
            fail("--manufacturer needs hex bytes", code: 2)
        }
        manufacturer = value
    default:
        fail("unknown argument: \(arg)", code: 2)
    }
}

guard let seconds, seconds.isFinite, seconds > 0, seconds <= 3600 else {
    fail("usage: advertise.swift --seconds N [--name NAME] [--manufacturer HEX]", code: 2)
}
guard !name.isEmpty, name.utf8.count <= 20 else {
    fail("local name must be 1..20 bytes so the advertisement stays under 31 bytes", code: 2)
}

let advertiser = Advertiser(name: name, manufacturer: manufacturer, seconds: seconds)
RunLoop.main.run()
