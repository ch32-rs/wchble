// Mac-side source sanity scanner: prints manufacturer data/local name for
// nearby peripherals. A scannable Android source should expose both the
// advertisement marker and the scan-response marker when CoreBluetooth merges
// the scan response into `advertisementData`.
import CoreBluetooth
import Foundation

final class Delegate: NSObject, CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
            print("scanning")
        } else {
            print("state \(central.state.rawValue)")
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        var parts: [String] = []
        if let data = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data {
            parts.append("mfr=" + data.map { String(format: "%02x", $0) }.joined())
        }
        if let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String {
            parts.append("name=\(name)")
        }
        if parts.isEmpty {
            return
        }
        print("\(peripheral.identifier.uuidString) rssi=\(RSSI) " +
              parts.joined(separator: " "))
    }
}

let seconds = CommandLine.arguments.count > 1 ? Double(CommandLine.arguments[1])! : 20
let delegate = Delegate()
let central = CBCentralManager(delegate: delegate, queue: nil)
DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { exit(0) }
RunLoop.main.run()
_ = central
