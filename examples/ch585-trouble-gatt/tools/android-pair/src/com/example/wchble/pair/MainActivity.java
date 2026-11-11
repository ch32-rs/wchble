package com.example.wchble.pair;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.util.Locale;
import java.util.UUID;

/**
 * S2 controlled central: connect to a "wch585-p4" peripheral, bond (Just Works),
 * then prove the GATT read/write path still works on the encrypted link.
 *
 * Every observable step is a single JSON line on logcat with tag WCHBLE so the
 * runner can validate the transcript without parsing UI text.
 */
public class MainActivity extends Activity {
    private static final String TAG = "WCHBLE";
    private static final String TARGET = "wch585-p4";
    private static final UUID SERVICE = UUID.fromString("00001000-b0cd-11ec-871f-d45ddf138840");
    private static final UUID VALUE = UUID.fromString("00001001-b0cd-11ec-871f-d45ddf138840");
    private static final int WRITE_VALUE = 0x2b;
    private static final int TIMEOUT_MS = 45_000;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private BluetoothAdapter adapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic valueCharacteristic;
    private String targetAddress;
    private boolean scanning;
    private boolean bonding;
    private boolean bonded;
    private boolean discovered;
    private boolean started;
    private boolean writeSent;
    private boolean verifyRead;
    private boolean done;
    private int reads;

    private final Runnable timeout = () -> finishRun(false, "timeout");

    private final BroadcastReceiver bondReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            if (device == null || targetAddress == null || !targetAddress.equals(device.getAddress())) {
                return;
            }
            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.ERROR);
            int previous = intent.getIntExtra(BluetoothDevice.EXTRA_PREVIOUS_BOND_STATE,
                    BluetoothDevice.ERROR);
            logEvent("\"event\":\"bond_state\",\"state\":%d,\"previous\":%d", state, previous);
            if (state == BluetoothDevice.BOND_BONDED) {
                bonded = true;
                maybeStartGatt();
            } else if (state == BluetoothDevice.BOND_NONE && previous == BluetoothDevice.BOND_BONDING) {
                finishRun(false, "bond_rejected");
            }
        }
    };

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            if (scanning && result.getDevice() != null) {
                String name = result.getScanRecord() != null
                        ? result.getScanRecord().getDeviceName() : null;
                if (name == null) {
                    name = result.getDevice().getName();
                }
                if (TARGET.equals(name)) {
                    scanning = false;
                    scanner.stopScan(this);
                    targetAddress = result.getDevice().getAddress();
                    logEvent("\"event\":\"found\",\"name\":\"%s\",\"address\":\"%s\",\"rssi\":%d",
                            name, targetAddress, result.getRssi());
                    logEvent("\"event\":\"connecting\",\"address\":\"%s\"", targetAddress);
                    gatt = result.getDevice().connectGatt(MainActivity.this, false, gattCallback,
                            BluetoothDevice.TRANSPORT_LE);
                    if (gatt == null) {
                        finishRun(false, "connect_gatt_null");
                    }
                }
            }
        }

        @Override
        public void onScanFailed(int errorCode) {
            finishRun(false, "scan_failed_" + errorCode);
        }
    };

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            logEvent("\"event\":\"connection_state\",\"status\":%d,\"state\":%d", status, newState);
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (!bonding) {
                    bonding = true;
                    boolean requested = g.getDevice().createBond();
                    logEvent("\"event\":\"bond_requested\",\"ok\":%s", requested);
                }
                if (!g.discoverServices()) {
                    finishRun(false, "discover_failed");
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (!done) {
                    finishRun(false, "disconnected");
                }
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            BluetoothGattService service = g.getService(SERVICE);
            BluetoothGattCharacteristic characteristic = service == null ? null : service.getCharacteristic(VALUE);
            logEvent("\"event\":\"services_discovered\",\"status\":%d,\"service\":%s,\"characteristic\":%s",
                    status, service != null, characteristic != null);
            if (status != BluetoothGatt.GATT_SUCCESS || characteristic == null) {
                finishRun(false, "service_missing");
                return;
            }
            valueCharacteristic = characteristic;
            discovered = true;
            maybeStartGatt();
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic characteristic,
                                         int status) {
            reads += 1;
            int value = valueOf(characteristic);
            logEvent("\"event\":\"read\",\"status\":%d,\"value\":%d,\"index\":%d", status, value, reads);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                finishRun(false, "read_failed");
                return;
            }
            if (verifyRead) {
                if (value == WRITE_VALUE) {
                    finishRun(true, "encrypted_read_write_ok");
                } else {
                    finishRun(false, "verify_mismatch");
                }
                return;
            }
            // First read proves encrypted access; then write and read back.
            characteristic.setValue(le32(WRITE_VALUE));
            characteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            writeSent = g.writeCharacteristic(characteristic);
            logEvent("\"event\":\"write_requested\",\"ok\":%s,\"value\":%d", writeSent, WRITE_VALUE);
            if (!writeSent) {
                finishRun(false, "write_start_failed");
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic characteristic,
                                          int status) {
            logEvent("\"event\":\"write_ack\",\"status\":%d", status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                finishRun(false, "write_failed");
                return;
            }
            verifyRead = true;
            if (!g.readCharacteristic(characteristic)) {
                finishRun(false, "verify_read_start_failed");
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(new android.view.View(this));
        if (checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            finishRun(false, "permissions_missing");
            return;
        }
        BluetoothManager manager = getSystemService(BluetoothManager.class);
        adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            finishRun(false, "bluetooth_disabled");
            return;
        }
        scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) {
            finishRun(false, "scanner_missing");
            return;
        }
        registerReceiver(bondReceiver, new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED),
                Context.RECEIVER_NOT_EXPORTED);
        handler.postDelayed(timeout, TIMEOUT_MS);
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();
        scanning = true;
        logEvent("\"event\":\"scan_started\",\"target\":\"%s\"", TARGET);
        scanner.startScan(null, settings, scanCallback);
    }

    private void maybeStartGatt() {
        if (done || started || !bonded || !discovered || valueCharacteristic == null) {
            return;
        }
        started = true;
        logEvent("\"event\":\"encrypted_gatt_start\"");
        if (!gatt.readCharacteristic(valueCharacteristic)) {
            finishRun(false, "read_start_failed");
        }
    }

    private int valueOf(BluetoothGattCharacteristic characteristic) {
        byte[] bytes = characteristic.getValue();
        if (bytes == null || bytes.length < 4) {
            return -1;
        }
        return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8)
                | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24);
    }

    private static byte[] le32(int value) {
        return new byte[]{(byte) value, (byte) (value >> 8), (byte) (value >> 16), (byte) (value >> 24)};
    }

    private void logEvent(String fmt, Object... args) {
        Log.i(TAG, String.format(Locale.US,
                "{\"t_ms\":%d," + fmt + "}", SystemClock.elapsedRealtime(), args));
    }

    private void finishRun(boolean pass, String reason) {
        if (done) {
            return;
        }
        done = true;
        handler.removeCallbacks(timeout);
        logEvent("\"event\":\"summary\",\"pass\":%s,\"reason\":\"%s\",\"bonder\":%s,"
                        + "\"bonded\":%s,\"reads\":%d,\"wrote\":%s",
                pass, reason, bonding, bonded, reads, writeSent);
        if (gatt != null) {
            try {
                gatt.disconnect();
                gatt.close();
            } catch (RuntimeException ignored) {
                // Best effort: the log line is the evidence.
            }
        }
        handler.postDelayed(this::finish, 300);
    }

    @Override
    protected void onDestroy() {
        done = true;
        handler.removeCallbacks(timeout);
        try {
            unregisterReceiver(bondReceiver);
        } catch (RuntimeException ignored) {
            // Not registered.
        }
        if (scanner != null && scanning) {
            try {
                scanner.stopScan(scanCallback);
            } catch (RuntimeException ignored) {
                // Adapter may be off.
            }
        }
        super.onDestroy();
    }
}
