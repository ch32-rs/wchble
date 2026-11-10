// Controlled GATT peripheral for the C1 CH585 central bring-up.
//
// CoreBluetooth's peripheral role has no connection callbacks, so first
// read/write is the observable connection evidence. The local name is the only
// advertising field: with a 128-bit service UUID beside it the name would move
// to the scan response, which the passive C1 scanner cannot see.
import CoreBluetooth
import Foundation

let initialValue: UInt32 = 0x2a
let serviceUuid = CBUUID(string: "00001000-B0CD-11EC-871F-D45DDF138840")
let characteristicUuid = CBUUID(string: "00001001-B0CD-11EC-871F-D45DDF138840")
let started = Date()

func log(_ fields: [String: Any]) {
    var row = fields
    row["monotonic_seconds"] = Date().timeIntervalSince(started)
    guard let data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]),
          let text = String(data: data, encoding: .utf8) else { return }
    print(text)
    fflush(stdout)
}

final class Peripheral: NSObject, CBPeripheralManagerDelegate {
    let name: String
    let service: CBMutableService
    let characteristic: CBMutableCharacteristic
    var manager: CBPeripheralManager!
    var value: UInt32 = initialValue
    var reads = 0
    var writes = 0
    var subscribed = 0

    init(name: String) {
        self.name = name
        characteristic = CBMutableCharacteristic(
            type: characteristicUuid,
            properties: [.read, .write, .notify],
            value: nil,
            permissions: [.readable, .writeable])
        service = CBMutableService(type: serviceUuid, primary: true)
        service.characteristics = [characteristic]
        super.init()
        manager = CBPeripheralManager(delegate: self, queue: nil)
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let state: String
        switch peripheral.state {
        case .poweredOn: state = "poweredOn"
        case .poweredOff: state = "poweredOff"
        case .unauthorized: state = "unauthorized"
        case .unsupported: state = "unsupported"
        case .resetting: state = "resetting"
        case .unknown: state = "unknown"
        @unknown default: state = "future"
        }
        log(["event": "state", "state": state])
        if peripheral.state == .poweredOn {
            peripheral.add(service)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didAdd service: CBService, error: Error?) {
        if let error = error {
            log(["event": "error", "stage": "add_service", "message": error.localizedDescription])
            return
        }
        log(["event": "service_added", "service": serviceUuid.uuidString])
        startAdvertising()
    }

    func startAdvertising() {
        guard manager.state == .poweredOn else { return }
        manager.stopAdvertising()
        manager.startAdvertising([
            CBAdvertisementDataLocalNameKey: name,
        ])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error = error {
            log(["event": "error", "stage": "advertise", "message": error.localizedDescription])
            return
        }
        log(["event": "advertising", "name": name])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didReceiveRead request: CBATTRequest) {
        if request.characteristic.uuid != characteristicUuid {
            peripheral.respond(to: request, withResult: .requestNotSupported)
            return
        }
        var data = value.littleEndian
        let bytes = withUnsafeBytes(of: &data) { Data($0) }
        if request.offset > bytes.count {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }
        request.value = bytes.subdata(in: request.offset..<bytes.count)
        reads += 1
        log(["event": "read", "value": Int(value), "offset": request.offset,
             "reads": reads, "connected": reads + writes > 0])
        peripheral.respond(to: request, withResult: .success)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard request.characteristic.uuid == characteristicUuid,
                  let data = request.value, !data.isEmpty else {
                peripheral.respond(to: request, withResult: .requestNotSupported)
                continue
            }
            var raw: UInt32 = 0
            for (index, byte) in data.prefix(4).enumerated() {
                raw |= UInt32(byte) << (8 * index)
            }
            value = raw
            writes += 1
            log(["event": "write", "value": Int(value), "bytes": data.count,
                 "writes": writes, "connected": reads + writes > 0])
        }
        peripheral.respond(to: requests.first!, withResult: .success)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        subscribed += 1
        log(["event": "subscribed", "subscribed": subscribed])
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        log(["event": "unsubscribed"])
    }

    func summary() {
        log(["event": "summary", "name": name, "reads": reads, "writes": writes,
             "subscribed": subscribed, "exit_code": 0,
             "reason": reads + writes > 0 ? "traffic_seen" : "no_traffic"])
    }
}

let args = CommandLine.arguments
func option(_ name: String, _ fallback: String) -> String {
    guard let index = args.firstIndex(of: name), index + 1 < args.count else { return fallback }
    return args[index + 1]
}

let name = option("--name", "wch585-c1")
let timeout = Double(option("--timeout", "45")) ?? 45
let peripheral = Peripheral(name: name)
let deadline = Date().addingTimeInterval(timeout)
log(["event": "start", "name": name, "timeout_seconds": timeout,
     "service": serviceUuid.uuidString, "characteristic": characteristicUuid.uuidString,
     "initial": Int(initialValue)])

while Date() < deadline {
    RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.25))
}
peripheral.summary()
exit(0)
