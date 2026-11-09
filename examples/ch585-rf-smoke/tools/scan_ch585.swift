#!/usr/bin/env swift
// Check discovery only; CoreBluetooth cannot measure packet timing or channel.
import CoreBluetooth
import Foundation

final class Scanner: NSObject, CBCentralManagerDelegate {
    private let target: String
    private var central: CBCentralManager!
    private var observations = 0
    private var started = false

    init(target: String, seconds: TimeInterval) {
        self.target = target
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in
            self?.finish()
        }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            guard !started else { return }
            started = true
            central.scanForPeripherals(withServices: nil, options: [
                CBCentralManagerScanOptionAllowDuplicatesKey: true
            ])
        case .unknown, .resetting:
            break
        default:
            fputs("Bluetooth unavailable: state=\(central.state.rawValue)\n", stderr)
            exit(2)
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        // Use the current advertisement data rather than the cached peripheral name.
        guard let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String,
              name == target else { return }
        observations += 1
        print("seen name=\(name) rssi=\(RSSI) id=\(peripheral.identifier.uuidString)")
    }

    private func finish() -> Never {
        central.stopScan()
        print("observations=\(observations) target=\(target)")
        if !started {
            fputs("Bluetooth did not become ready before the deadline\n", stderr)
            exit(2)
        }
        exit(observations > 0 ? 0 : 1)
    }
}

let args = CommandLine.arguments
let target = args.count > 1 ? args[1] : "wch585"
let seconds = args.count > 2 ? (Double(args[2]) ?? 0) : 10
if target.isEmpty || !seconds.isFinite || seconds <= 0 || seconds > 3600 {
    fputs("usage: scan_ch585.swift [exact-name] [seconds (0, 3600]]\n", stderr)
    exit(2)
}
let scanner = Scanner(target: target, seconds: seconds)
RunLoop.main.run()
