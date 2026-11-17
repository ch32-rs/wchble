// Differential peripheral: the same GATT shape as the CH585 secure firmware,
// served by macOS CoreBluetooth. It exists only to answer one question with a
// known-good controller underneath: does this phone's controller send
// LL_START_ENC_REQ at all? Every state change is a JSON line on stdout.
import CoreBluetooth
import Foundation

let serviceUUID = CBUUID(string: "00001000-b0cd-11ec-871f-d45ddf138840")
let valueUUID = CBUUID(string: "00001001-b0cd-11ec-871f-d45ddf138840")
let localName = "wch585-p4"

func log(_ line: String) {
    FileHandle.standardOutput.write((line + "\n").data(using: .utf8)!)
}

final class Peripheral: NSObject, CBPeripheralManagerDelegate {
    var manager: CBPeripheralManager!
    var value: [UInt8] = [0x2a, 0x00, 0x00, 0x00]
    var advertising = false

    func start() {
        manager = CBPeripheralManager(delegate: self, queue: nil)
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        log("{\"event\":\"state\",\"state\":\(peripheral.state.rawValue)}")
        guard peripheral.state == .poweredOn else { return }
        let characteristic = CBMutableCharacteristic(
            type: valueUUID,
            properties: [.read, .write, .notify],
            value: nil,
            permissions: [.readEncryptionRequired, .writeEncryptionRequired])
        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [characteristic]
        manager.add(service)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService,
                           error: Error?) {
        log("{\"event\":\"service\",\"error\":\"\(error?.localizedDescription ?? "")\"}")
        advertise()
    }

    func advertise() {
        advertising = true
        // Only the name fits: flags + 128-bit UUID + name exceeds the 31-byte
        // legacy advertising data, and macOS drops the name when it does not.
        manager.startAdvertising([CBAdvertisementDataLocalNameKey: localName])
        log("{\"event\":\"advertising\",\"name\":\"\(localName)\"}")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        request.value = Data(value)
        manager.respond(to: request, withResult: .success)
        log("{\"event\":\"read\",\"offset\":\(request.offset)}")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            let bytes = [UInt8](request.value ?? Data())
            value = Array(bytes.prefix(4)) + Array(repeating: 0, count: max(0, 4 - bytes.count))
            value = Array(value.prefix(4))
            log("{\"event\":\"write\",\"value\":\(value)}")
        }
        guard let first = requests.first else { return }
        manager.respond(to: first, withResult: .success)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        log("{\"event\":\"subscribed\"}")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        log("{\"event\":\"unsubscribed\"}")
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        log("{\"event\":\"ready\"}")
    }
}

let peripheral = Peripheral()
peripheral.start()
// Recover if the system stopped advertising (the API reports no failure reason).
Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
    guard let manager = peripheral.manager else { return }
    if manager.state == .poweredOn && !manager.isAdvertising {
        peripheral.advertise()
    }
}
log("{\"event\":\"started\"}")
RunLoop.main.run()
