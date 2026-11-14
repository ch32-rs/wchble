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
    // Default target for the S2 peripheral; `--es target_name` overrides it so
    // the same pairing transcript can be taken against a vendor EVT example.
    private String targetName = "wch585-p4";
    private static final UUID SERVICE = UUID.fromString("00001000-b0cd-11ec-871f-d45ddf138840");
    private static final UUID VALUE = UUID.fromString("00001001-b0cd-11ec-871f-d45ddf138840");
    private static final UUID CONTROL = UUID.fromString("00001002-b0cd-11ec-871f-d45ddf138840");
    private static final int WRITE_VALUE = 0x2b;
    private static final int TIMEOUT_MS = 45_000;
    // `--es mode` selects the S3 acceptance phase. `pair` is the S2 flow.
    private String mode = "pair";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private BluetoothAdapter adapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic valueCharacteristic;
    private BluetoothGattCharacteristic controlCharacteristic;
    private String targetAddress;
    private boolean scanning;
    private boolean bonding;
    private boolean bonded;
    private boolean discovered;
    private boolean started;
    private boolean writeSent;
    private boolean verifyRead;
    private boolean controlWrite;
    private boolean done;
    private int reads;
    private int scanReports;
    private boolean authRetried;
    private boolean serviceMissing;
    private boolean scanOnly;

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
                // BONDED is set when SMP finishes; the controller starts the
                // LL encryption procedure after that. Give it time so the
                // transcript's read/write really travel encrypted.
                handler.postDelayed(() -> {
                    logEvent("\"event\":\"bond_settled\"");
                    maybeStartGatt();
                }, 2000);
            } else if (state == BluetoothDevice.BOND_NONE && previous == BluetoothDevice.BOND_BONDING) {
                finishRun(false, "bond_rejected");
            }
        }
    };

    // Android shows a consent dialog for Just Works pairing whenever the local
    // IO capability is display-capable, even though our Pairing Response asks
    // for NoInputNoOutput/MITM-off. The broadcast arrives from the Bluetooth
    // stack process (so the receiver must be exported), but this ROM requires
    // BLUETOOTH_PRIVILEGED for setPairingConfirmation; the runner therefore
    // taps the system dialog and logs the variant for evidence.
    // BluetoothDevice.PAIRING_VARIANT_CONSENT is @SystemApi, so mirror its value.
    private static final int PAIRING_VARIANT_CONSENT = 3;

    private final BroadcastReceiver pairingReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            if (device == null || targetAddress == null || !targetAddress.equals(device.getAddress())) {
                return;
            }
            int variant = intent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT, -1);
            logEvent("\"event\":\"pairing_request\",\"variant\":%d", variant);
            if (variant == PAIRING_VARIANT_CONSENT) {
                boolean confirmed;
                try {
                    confirmed = device.setPairingConfirmation(true);
                } catch (SecurityException denied) {
                    logEvent("\"event\":\"pairing_confirm\",\"accepted\":false,"
                            + "\"error\":\"bluetooth_privileged\"");
                    return;
                }
                logEvent("\"event\":\"pairing_confirm\",\"accepted\":%s",
                        confirmed ? "true" : "false");
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
                scanReports += 1;
                if (scanReports <= 16) {
                    logEvent("\"event\":\"scan_report\",\"name\":\"%s\",\"address\":\"%s\",\"rssi\":%d",
                            name == null ? "" : name, result.getDevice().getAddress(), result.getRssi());
                }
                if (targetName.equals(name)) {
                    scanning = false;
                    scanner.stopScan(this);
                    targetAddress = result.getDevice().getAddress();
                    logEvent("\"event\":\"found\",\"name\":\"%s\",\"address\":\"%s\",\"rssi\":%d",
                            name, targetAddress, result.getRssi());
                    if (scanOnly) {
                        return;
                    }
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
                    boolean peerBonded =
                            g.getDevice().getBondState() == BluetoothDevice.BOND_BONDED;
                    if (peerBonded) {
                        bonded = true;
                        logEvent("\"event\":\"already_bonded\"");
                    }
                    if ("wipe".equals(mode)) {
                        // Setup phase: the control write needs no encryption,
                        // so it works even when the Host still holds a stale
                        // bond this phone cannot use.
                        logEvent("\"event\":\"control_only\"");
                    } else if ("reconnect".equals(mode)) {
                        // The whole point of S3: the controller must resume
                        // the stored keys, so never ask for a new bond here.
                        if (!peerBonded) {
                            finishRun(false, "reconnect_not_bonded");
                            return;
                        }
                    } else if (!peerBonded) {
                        if (!"pair".equals(mode)) {
                            // delete/fault act on the bond this phone and the
                            // Host already share.
                            finishRun(false, "not_bonded");
                            return;
                        }
                        boolean requested = g.getDevice().createBond();
                        logEvent("\"event\":\"bond_requested\",\"ok\":%s", requested);
                    }
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
            BluetoothGattCharacteristic control = service == null ? null : service.getCharacteristic(CONTROL);
            logEvent("\"event\":\"services_discovered\",\"status\":%d,\"service\":%s,\"characteristic\":%s,"
                            + "\"control\":%s",
                    status, service != null, characteristic != null, control != null);
            boolean controlOnly = "wipe".equals(mode);
            if (status != BluetoothGatt.GATT_SUCCESS
                    || (controlOnly ? control == null : characteristic == null)) {
                // Differential mode: a vendor peripheral serves other GATT
                // services, so this run only proves the pairing/encryption
                // transcript. Wait for the bond, then pass on that alone.
                serviceMissing = true;
                maybeStartGatt();
                return;
            }
            valueCharacteristic = characteristic;
            controlCharacteristic = control;
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
                // A bonded reconnect may need the stack to encrypt first; one
                // delayed retry covers the 0x05/0x0F authentication errors.
                if (!authRetried && (status == 5 || status == 15)) {
                    authRetried = true;
                    handler.postDelayed(() -> g.readCharacteristic(characteristic), 2000);
                    logEvent("\"event\":\"read_retry\"");
                    return;
                }
                finishRun(false, "read_failed");
                return;
            }
            if (verifyRead) {
                if (value == WRITE_VALUE) {
                    finishRun(true, reason());
                } else {
                    finishRun(false, "verify_mismatch");
                }
                return;
            }
            // First read proves encrypted access. Control modes then send the
            // bond command; the S2 flow writes the value and reads it back.
            if (isControlMode()) {
                controlWrite = true;
                logEvent("\"event\":\"control_write\",\"command\":\"%s\"", controlName());
                if (!writeControl()) {
                    finishRun(false, "write_start_failed");
                }
                return;
            }
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
            if (controlWrite) {
                finishRun(true, reason());
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
        String requestedTarget = getIntent().getStringExtra("target_name");
        if (requestedTarget != null && !requestedTarget.isEmpty()) {
            targetName = requestedTarget;
        }
        String requestedMode = getIntent().getStringExtra("mode");
        if (requestedMode != null) {
            if (!requestedMode.matches("pair|reconnect|delete|wipe|fault")) {
                finishRun(false, "unknown_mode");
                return;
            }
            mode = requestedMode;
        }
        logEvent("\"event\":\"mode\",\"mode\":\"%s\"", mode);
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
        // Bond state also arrives from the Bluetooth stack process; a
        // non-exported receiver silently never fires (no run ever logged one).
        registerReceiver(bondReceiver, new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED),
                Context.RECEIVER_EXPORTED);
        // These broadcasts come from the Bluetooth stack process, not ours:
        // a non-exported receiver never sees them (the Settings pairing dialog
        // then appears and nothing confirms it).
        registerReceiver(pairingReceiver, new IntentFilter(BluetoothDevice.ACTION_PAIRING_REQUEST),
                Context.RECEIVER_EXPORTED);
        scanOnly = getIntent().getBooleanExtra("scan_only", false);
        if (scanOnly) {
            // Address discovery only: the vendor differential needs the peer's
            // public address for the sniffer's --follow before connecting.
            handler.postDelayed(() -> finishRun(true, "scan_only_done"), 10_000);
        } else {
            handler.postDelayed(timeout, TIMEOUT_MS);
        }
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();
        scanning = true;
        logEvent("\"event\":\"scan_started\",\"target\":\"%s\"", targetName);
        scanner.startScan(null, settings, scanCallback);
    }

    private void maybeStartGatt() {
        if (done || started) {
            return;
        }
        if (serviceMissing) {
            boolean s3Run = isControlMode() || "reconnect".equals(mode);
            if (s3Run) {
                started = true;
                finishRun(false, "service_missing");
            } else if (bonded) {
                started = true;
                finishRun(true, "paired_no_service");
            }
            return;
        }
        if ("wipe".equals(mode)) {
            // Setup only: no encrypted access is possible yet, so go straight
            // to the control write once discovery succeeded.
            if (!discovered || controlCharacteristic == null) {
                return;
            }
            started = true;
            controlWrite = true;
            logEvent("\"event\":\"control_start\",\"command\":\"%s\"", controlName());
            if (!writeControl()) {
                finishRun(false, "write_start_failed");
            }
            return;
        }
        if (!bonded || !discovered || valueCharacteristic == null) {
            return;
        }
        started = true;
        logEvent("\"event\":\"encrypted_gatt_start\"");
        if (!gatt.readCharacteristic(valueCharacteristic)) {
            finishRun(false, "read_start_failed");
        }
    }

    /** delete/wipe/fault talk to the bond control characteristic. */
    private boolean isControlMode() {
        return "delete".equals(mode) || "wipe".equals(mode) || "fault".equals(mode);
    }

    /** Summary reason the runner matches for this mode. */
    private String reason() {
        switch (mode) {
            case "reconnect":
                return "reconnect_encrypted_read_write_ok";
            case "delete":
                return "bond_delete_ok";
            case "wipe":
                return "bond_wipe_ok";
            case "fault":
                return "fault_injected_ok";
            default:
                return "encrypted_read_write_ok";
        }
    }

    private String controlName() {
        switch (mode) {
            case "wipe":
                return "WIPE";
            case "delete":
                return "DEL!";
            case "fault":
                return "FALT";
            default:
                return "";
        }
    }

    private int controlCommand() {
        return le32Of(controlName());
    }

    private static int le32Of(String text) {
        return (text.charAt(0) & 0xff) | ((text.charAt(1) & 0xff) << 8)
                | ((text.charAt(2) & 0xff) << 16) | ((text.charAt(3) & 0xff) << 24);
    }

    private boolean writeControl() {
        if (controlCharacteristic == null) {
            return false;
        }
        controlCharacteristic.setValue(le32(controlCommand()));
        controlCharacteristic.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        writeSent = gatt.writeCharacteristic(controlCharacteristic);
        logEvent("\"event\":\"write_requested\",\"ok\":%s,\"value\":%d", writeSent,
                controlCommand());
        return writeSent;
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
        Object[] values = new Object[args.length + 1];
        values[0] = SystemClock.elapsedRealtime();
        System.arraycopy(args, 0, values, 1, args.length);
        Log.i(TAG, String.format(Locale.US, "{\"t_ms\":%d," + fmt + "}", values));
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
        // The runner waits for `pidof` to become empty; finishing the activity
        // alone leaves a cached process behind on Android 15, so end it here
        // after the summary line has been written.
        handler.postDelayed(() -> {
            finish();
            handler.postDelayed(() -> android.os.Process.killProcess(
                    android.os.Process.myPid()), 300);
        }, 300);
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
        try {
            unregisterReceiver(pairingReceiver);
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
