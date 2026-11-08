#!/usr/bin/env swift
// Scan for BLE advertiser local name "wchble" for a few seconds.
import Foundation
import CoreBluetooth

final class Scanner: NSObject, CBCentralManagerDelegate {
    let target = "wchble"
    var central: CBCentralManager!
    var found = false
    let deadline: Date

    init(seconds: TimeInterval) {
        self.deadline = Date().addingTimeInterval(seconds)
        super.init()
        self.central = CBCentralManager(delegate: self, queue: nil)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            fputs("bluetooth state=\(central.state.rawValue)\n", stderr)
            if central.state != .unknown && central.state != .resetting {
                exit(2)
            }
            return
        }
        print("scanning for local name '\(target)' …")
        central.scanForPeripherals(withServices: nil, options: [
            CBCentralManagerScanOptionAllowDuplicatesKey: true
        ])
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? peripheral.name
            ?? ""
        let addr = peripheral.identifier.uuidString
        if !name.isEmpty {
            print(String(format: "seen name=%@ rssi=%@ id=%@", name, RSSI, addr))
        }
        if name.localizedCaseInsensitiveContains(target) {
            print("FOUND \(name) rssi=\(RSSI) id=\(addr)")
            found = true
            central.stopScan()
            exit(0)
        }
        if Date() > deadline {
            fputs("timeout: '\(target)' not seen\n", stderr)
            exit(1)
        }
    }
}

let seconds = CommandLine.arguments.dropFirst().first.flatMap(Double.init) ?? 12
let _scanner = Scanner(seconds: seconds)
RunLoop.main.run()
