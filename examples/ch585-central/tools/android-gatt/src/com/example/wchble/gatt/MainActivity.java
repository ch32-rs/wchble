package com.example.wchble.gatt;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.view.WindowManager;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

/**
 * Controlled GATT peripheral for the CH585 C1 central test.
 *
 * The C1 scans passively, so it only sees the advertising PDU. The complete
 * local name therefore has to live in the legacy ADV_IND itself: this app
 * advertises connectable (which selects ADV_IND, inherently scannable), sets
 * include-device-name, and deliberately adds no 128-bit service UUID and no
 * TX power element. A 128-bit UUID alone is 18 bytes and would push the name
 * into the scan response, where a passive scanner cannot see it.
 *
 * Every event is one JSON line on logcat tag WCHBLE.
 */
public final class MainActivity extends Activity {
    private static final String TAG = "WCHBLE";

    private static final UUID SERVICE_UUID =
            UUID.fromString("00001000-b0cd-11ec-871f-d45ddf138840");
    private static final UUID CHARACTERISTIC_UUID =
            UUID.fromString("00001001-b0cd-11ec-871f-d45ddf138840");
    // Android's GATT server does not synthesize this for NOTIFY characteristics;
    // the app must publish it. BlueZ/CoreBluetooth clients (and trouble-host's
    // characteristic discovery) require it to resolve the notification channel.
    private static final UUID CCCD_UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    private static final int INITIAL_VALUE = 0x0000002A;
    private static final int LEGACY_ADV_MAX_BYTES = 31;
    private static final long NAME_POLL_MS = 250;
    private static final int NAME_POLL_TRIES = 12; // ~3 s for asynchronous setName
    private static final long NAME_SETTLE_MS = 400; // let the controller local name catch up
    private static final long RESTART_DELAY_MS = 500;
    private static final long RESTART_SETTLE_MS = 250;

    private static final String[] RUNTIME_PERMISSIONS = {
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
    };

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final long startElapsed = SystemClock.elapsedRealtime();

    private BluetoothAdapter adapter;
    private BluetoothLeAdvertiser advertiser;
    private BluetoothGattServer gattServer;
    private BluetoothGattCharacteristic characteristic;

    private Runnable restartRunnable;
    private Runnable timeoutRunnable;
    private Runnable delayedRestartRunnable;

    private String name = "wch585-c1";
    private boolean noService;
    private int timeoutSeconds = 90;
    // Test-only: delay ATT read responses so the runner can take the adapter
    // down while a request is outstanding.
    private int holdMs;
    private int value = INITIAL_VALUE;
    private int reads;
    private int writes;
    private int connections;
    private int disconnections;
    private int readvertisings;
    private int alreadyStartedRetries;
    private int advertisedBytes;
    private boolean stopping;
    private boolean finished;

    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            if (finished || stopping) {
                return;
            }
            alreadyStartedRetries = 0;
            logEvent("\"event\":\"advertising\",\"name\":" + quote(name)
                    + ",\"adapter_name\":" + quote(adapterName())
                    + ",\"address\":" + quote(localAddress())
                    + ",\"adv_bytes\":" + advertisedBytes
                    + ",\"mode\":" + settingsInEffect.getMode()
                    + ",\"tx_power\":" + settingsInEffect.getTxPowerLevel()
                    + ",\"connectable\":" + settingsInEffect.isConnectable());
        }

        @Override
        public void onStartFailure(int errorCode) {
            if (finished || stopping) {
                return;
            }
            if (errorCode == AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED
                    && alreadyStartedRetries < 2) {
                // Harmless race after a disconnect restart: stop and try again.
                alreadyStartedRetries++;
                logEvent("\"event\":\"advertise_failed\""
                        + ",\"error\":" + errorCode
                        + ",\"reason\":" + quote(advertiseErrorName(errorCode))
                        + ",\"retry\":" + alreadyStartedRetries
                        + ",\"adv_bytes\":" + advertisedBytes);
                if (advertiser != null) {
                    try {
                        advertiser.stopAdvertising(this);
                    } catch (RuntimeException ignored) {
                        // Already stopped.
                    }
                }
                handler.postDelayed(() -> startAdvertising(true), RESTART_SETTLE_MS * 2);
                return;
            }
            logEvent("\"event\":\"advertise_failed\""
                    + ",\"error\":" + errorCode
                    + ",\"reason\":" + quote(advertiseErrorName(errorCode))
                    + ",\"adv_bytes\":" + advertisedBytes);
            finishWithSummary("advertise_failed");
        }
    };

    private final BluetoothGattServerCallback serverCallback = new BluetoothGattServerCallback() {
        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState) {
            if (finished || stopping) {
                return;
            }
            String address = addressOf(device);
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connections++;
                logEvent("\"event\":\"connected\",\"address\":" + quote(address)
                        + ",\"status\":" + status
                        + ",\"connections\":" + connections);
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                disconnections++;
                logEvent("\"event\":\"disconnected\",\"address\":" + quote(address)
                        + ",\"status\":" + status
                        + ",\"connections\":" + connections
                        + ",\"disconnections\":" + disconnections);
                scheduleAdvertisingRestart();
            }
        }

        @Override
        public void onServiceAdded(int status, BluetoothGattService service) {
            if (finished || stopping) {
                return;
            }
            if (status == BluetoothGatt.GATT_SUCCESS) {
                logEvent("\"event\":\"service_added\",\"service\":\""
                        + service.getUuid() + "\",\"status\":" + status);
                startAdvertising(false);
            } else {
                logEvent("\"event\":\"error\",\"stage\":\"service_added\""
                        + ",\"service\":\"" + service.getUuid() + "\""
                        + ",\"status\":" + status);
                finishWithSummary("service_add_failed");
            }
        }

        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId,
                int offset, BluetoothGattCharacteristic requested) {
            if (finished || stopping) {
                return;
            }
            String address = addressOf(device);
            if (!CHARACTERISTIC_UUID.equals(requested.getUuid())) {
                respond(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null);
                logEvent("\"event\":\"read\",\"address\":" + quote(address)
                        + ",\"offset\":" + offset
                        + ",\"status\":" + BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                        + ",\"reason\":\"unknown_characteristic\"");
                return;
            }
            byte[] bytes = valueBytes();
            if (offset < 0 || offset > bytes.length) {
                respond(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, offset, null);
                logEvent("\"event\":\"read\",\"address\":" + quote(address)
                        + ",\"value\":" + value
                        + ",\"value_hex\":" + quote(hex32(value))
                        + ",\"offset\":" + offset
                        + ",\"status\":" + BluetoothGatt.GATT_INVALID_OFFSET
                        + ",\"reads\":" + reads
                        + ",\"reason\":\"invalid_offset\"");
                return;
            }
            final byte[] slice = Arrays.copyOfRange(bytes, offset, bytes.length);
            if (holdMs > 0) {
                final int heldRequestId = requestId;
                final int heldOffset = offset;
                handler.postDelayed(() -> {
                    boolean sent = respond(device, heldRequestId,
                            BluetoothGatt.GATT_SUCCESS, heldOffset, slice);
                    reads++;
                    logEvent("\"event\":\"read\",\"address\":" + quote(address)
                            + ",\"value\":" + value
                            + ",\"offset\":" + heldOffset
                            + ",\"length\":" + slice.length
                            + ",\"held_ms\":" + holdMs
                            + ",\"status\":" + BluetoothGatt.GATT_SUCCESS
                            + ",\"sent\":" + sent
                            + ",\"reads\":" + reads);
                }, holdMs);
                logEvent("\"event\":\"read_held\",\"address\":" + quote(address)
                        + ",\"hold_ms\":" + holdMs
                        + ",\"reads\":" + reads);
                return;
            }
            boolean sent = respond(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice);
            reads++;
            logEvent("\"event\":\"read\",\"address\":" + quote(address)
                    + ",\"value\":" + value
                    + ",\"value_hex\":" + quote(hex32(value))
                    + ",\"offset\":" + offset
                    + ",\"length\":" + slice.length
                    + ",\"status\":" + BluetoothGatt.GATT_SUCCESS
                    + ",\"sent\":" + sent
                    + ",\"reads\":" + reads);
        }

        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId,
                BluetoothGattCharacteristic requested, boolean preparedWrite,
                boolean responseNeeded, int offset, byte[] requestValue) {
            if (finished || stopping) {
                return;
            }
            String address = addressOf(device);
            if (!CHARACTERISTIC_UUID.equals(requested.getUuid())) {
                if (responseNeeded) {
                    respond(device, requestId,
                            BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null);
                }
                logEvent("\"event\":\"write\",\"address\":" + quote(address)
                        + ",\"status\":" + BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                        + ",\"reason\":\"unknown_characteristic\"");
                return;
            }
            if (requestValue == null || requestValue.length == 0) {
                if (responseNeeded) {
                    respond(device, requestId,
                            BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, offset, null);
                }
                logEvent("\"event\":\"write\",\"address\":" + quote(address)
                        + ",\"status\":" + BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH
                        + ",\"reason\":\"empty_value\"");
                return;
            }
            int raw = 0;
            int count = Math.min(4, requestValue.length);
            for (int i = 0; i < count; i++) {
                raw |= (requestValue[i] & 0xFF) << (8 * i);
            }
            value = raw;
            if (characteristic != null) {
                characteristic.setValue(valueBytes());
            }
            if (responseNeeded) {
                respond(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null);
            }
            writes++;
            logEvent("\"event\":\"write\",\"address\":" + quote(address)
                    + ",\"value\":" + value
                    + ",\"value_hex\":" + quote(hex32(value))
                    + ",\"bytes\":" + requestValue.length
                    + ",\"offset\":" + offset
                    + ",\"prepared\":" + preparedWrite
                    + ",\"response_needed\":" + responseNeeded
                    + ",\"status\":" + BluetoothGatt.GATT_SUCCESS
                    + ",\"writes\":" + writes);
        }

        @Override
        public void onDescriptorReadRequest(BluetoothDevice device, int requestId,
                int offset, BluetoothGattDescriptor descriptor) {
            if (finished || stopping) {
                return;
            }
            respond(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null);
        }

        @Override
        public void onDescriptorWriteRequest(BluetoothDevice device, int requestId,
                BluetoothGattDescriptor descriptor, boolean preparedWrite,
                boolean responseNeeded, int offset, byte[] requestValue) {
            if (finished || stopping) {
                return;
            }
            if (responseNeeded) {
                respond(device, requestId,
                        BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null);
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Keep the activity (and the advertising/GATT role) alive for the run.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        Intent intent = getIntent();
        String requestedName = intent == null ? null : intent.getStringExtra("name");
        if (requestedName != null && !requestedName.isEmpty()) {
            name = requestedName;
        }
        noService = intent != null && intent.getBooleanExtra("no_service", false);
        int requestedTimeout = intent == null ? 90 : intent.getIntExtra("timeout", 90);
        if (requestedTimeout > 0) {
            timeoutSeconds = requestedTimeout;
        }
        int requestedHold = intent == null ? 0 : intent.getIntExtra("hold_ms", 0);
        if (requestedHold > 0) {
            holdMs = requestedHold;
        }

        logEvent("\"event\":\"start\",\"name\":" + quote(name)
                + ",\"timeout_seconds\":" + timeoutSeconds
                + ",\"no_service\":" + noService
                + ",\"service\":\"" + SERVICE_UUID + "\""
                + ",\"characteristic\":\"" + CHARACTERISTIC_UUID + "\""
                + ",\"initial\":" + value
                + ",\"initial_hex\":" + quote(hex32(value))
                + ",\"hold_ms\":" + holdMs);

        timeoutRunnable = () -> {
            timeoutRunnable = null;
            finishWithSummary("timeout");
        };
        handler.postDelayed(timeoutRunnable, timeoutSeconds * 1000L);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            String missing = missingPermission();
            if (missing != null) {
                // Normally pre-granted by `adb install -g`; ask once otherwise.
                logEvent("\"event\":\"permission_request\",\"permission\":"
                        + quote(missing));
                requestPermissions(RUNTIME_PERMISSIONS, 1);
                return;
            }
        }
        start();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        String missing = missingPermission();
        if (missing != null) {
            logEvent("\"event\":\"error\",\"stage\":\"permissions\""
                    + ",\"reason\":" + quote("missing " + missing));
            finishWithSummary("missing_permission");
            return;
        }
        start();
    }

    private String missingPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null;
        }
        for (String permission : RUNTIME_PERMISSIONS) {
            if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                return permission;
            }
        }
        return null;
    }

    private void start() {
        if (finished) {
            return;
        }
        BluetoothManager manager =
                (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null) {
            logEvent("\"event\":\"error\",\"stage\":\"adapter\""
                    + ",\"reason\":\"unavailable\"");
            finishWithSummary("adapter_unavailable");
            return;
        }
        if (!adapter.isEnabled()) {
            logEvent("\"event\":\"error\",\"stage\":\"adapter\""
                    + ",\"reason\":\"disabled\"");
            finishWithSummary("adapter_disabled");
            return;
        }

        String current = adapterName();
        if (name.equals(current)) {
            logEvent("\"event\":\"adapter_name\",\"name\":" + quote(name)
                    + ",\"applied\":true,\"already_set\":true");
            openServer();
            return;
        }

        boolean accepted;
        try {
            accepted = adapter.setName(name);
        } catch (RuntimeException error) {
            accepted = false;
            logEvent("\"event\":\"error\",\"stage\":\"adapter_name\""
                    + ",\"reason\":" + quote(error.toString()));
        }
        logEvent("\"event\":\"adapter_name\",\"name\":" + quote(name)
                + ",\"before\":" + quote(current)
                + ",\"accepted\":" + accepted
                + ",\"waiting\":true");
        if (!accepted) {
            logEvent("\"event\":\"error\",\"stage\":\"adapter_name\""
                    + ",\"reason\":\"setName_rejected\"");
            openServer();
            return;
        }
        // setName is asynchronous; wait until the adapter reports the new name
        // (bounded) so advertising does not carry the previous local name.
        pollAdapterName(0);
    }

    private void pollAdapterName(int attempt) {
        if (finished || stopping) {
            return;
        }
        String current = adapterName();
        if (name.equals(current)) {
            logEvent("\"event\":\"adapter_name\",\"name\":" + quote(name)
                    + ",\"current\":" + quote(current)
                    + ",\"applied\":true"
                    + ",\"waited_ms\":" + (attempt * NAME_POLL_MS));
            // adapter.getName() may update before the controller's local name;
            // give the latter a moment before asking for include-device-name.
            handler.postDelayed(this::openServer, NAME_SETTLE_MS);
            return;
        }
        if (attempt >= NAME_POLL_TRIES) {
            logEvent("\"event\":\"error\",\"stage\":\"adapter_name\""
                    + ",\"reason\":\"not_applied\""
                    + ",\"requested\":" + quote(name)
                    + ",\"current\":" + quote(current));
            // Proceed anyway: a stale name will surface as a scan miss.
            openServer();
            return;
        }
        handler.postDelayed(() -> pollAdapterName(attempt + 1), NAME_POLL_MS);
    }

    private void openServer() {
        if (finished || stopping) {
            return;
        }
        BluetoothManager manager =
                (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        gattServer = manager == null ? null : manager.openGattServer(this, serverCallback);
        if (gattServer == null) {
            logEvent("\"event\":\"error\",\"stage\":\"gatt_server\""
                    + ",\"reason\":\"open_failed\"");
            finishWithSummary("open_gatt_server_failed");
            return;
        }

        if (noService) {
            // Negative phase: accept connections but publish no attribute, so
            // service discovery finds nothing.
            startAdvertising(false);
            return;
        }

        characteristic = new BluetoothGattCharacteristic(
                CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
                        | BluetoothGattCharacteristic.PERMISSION_WRITE);
        characteristic.setValue(valueBytes());
        BluetoothGattDescriptor cccd = new BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ | BluetoothGattDescriptor.PERMISSION_WRITE);
        cccd.setValue(new byte[] { 0, 0 });
        if (!characteristic.addDescriptor(cccd)) {
            logEvent("\"event\":\"error\",\"stage\":\"add_cccd\"");
            finishWithSummary("add_cccd_failed");
            return;
        }

        BluetoothGattService service = new BluetoothGattService(
                SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);
        if (!service.addCharacteristic(characteristic)) {
            logEvent("\"event\":\"error\",\"stage\":\"add_characteristic\"");
            finishWithSummary("add_characteristic_failed");
            return;
        }
        if (!gattServer.addService(service)) {
            logEvent("\"event\":\"error\",\"stage\":\"add_service\""
                    + ",\"service\":\"" + SERVICE_UUID + "\"");
            finishWithSummary("add_service_failed");
            return;
        }
        // onServiceAdded() starts advertising once the database is registered.
    }

    private void startAdvertising(boolean restart) {
        if (finished || stopping) {
            return;
        }
        if (adapter == null || !adapter.isEnabled()) {
            logEvent("\"event\":\"error\",\"stage\":\"advertise\""
                    + ",\"reason\":\"adapter_disabled\"");
            finishWithSummary("adapter_disabled");
            return;
        }
        BluetoothLeAdvertiser adv = adapter.getBluetoothLeAdvertiser();
        if (adv == null) {
            logEvent("\"event\":\"error\",\"stage\":\"advertise\""
                    + ",\"reason\":\"no_le_advertiser\"");
            finishWithSummary("no_le_advertiser");
            return;
        }
        advertiser = adv;

        // Flags AD element (3) + Complete Local Name AD element (2 + name).
        // AdvertiseData has no getter for the assembled payload, so size it
        // ourselves. The negative name "wch585-c1-neg" is 18 bytes in total.
        int nameBytes = name.getBytes(StandardCharsets.UTF_8).length;
        advertisedBytes = 3 + 2 + nameBytes;
        if (advertisedBytes > LEGACY_ADV_MAX_BYTES) {
            logEvent("\"event\":\"advertise_failed\""
                    + ",\"error\":" + AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE
                    + ",\"reason\":\"ADVERTISE_FAILED_DATA_TOO_LARGE\""
                    + ",\"adv_bytes\":" + advertisedBytes
                    + ",\"limit\":" + LEGACY_ADV_MAX_BYTES
                    + ",\"name_bytes\":" + nameBytes);
            finishWithSummary("advertise_failed");
            return;
        }

        // The name is the only data element: no 128-bit service UUID, no TX
        // power level. The name must be inside ADV_IND, not the scan response.
        AdvertiseData advData = new AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .setIncludeTxPowerLevel(false)
                .build();

        AdvertiseSettings.Builder settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .setConnectable(true)
                .setTimeout(0);
        if (Build.VERSION.SDK_INT >= 34) {
            // API 34 hint; connectable legacy advertising is already ADV_IND
            // (connectable + scannable), which is what the passive C1 sees.
            settings.setDiscoverable(true);
        }

        if (restart) {
            readvertisings++;
            logEvent("\"event\":\"readvertising\",\"name\":" + quote(name)
                    + ",\"attempt\":" + readvertisings
                    + ",\"adv_bytes\":" + advertisedBytes);
        }

        try {
            adv.startAdvertising(settings.build(), advData, advertiseCallback);
        } catch (RuntimeException error) {
            logEvent("\"event\":\"advertise_failed\",\"error\":-1"
                    + ",\"reason\":" + quote(error.toString()));
            finishWithSummary("advertise_failed");
        }
    }

    private void scheduleAdvertisingRestart() {
        if (finished || stopping) {
            return;
        }
        if (restartRunnable != null) {
            handler.removeCallbacks(restartRunnable);
        }
        restartRunnable = () -> {
            restartRunnable = null;
            restartAdvertising();
        };
        handler.postDelayed(restartRunnable, RESTART_DELAY_MS);
    }

    private void restartAdvertising() {
        if (finished || stopping) {
            return;
        }
        // The controller may already have stopped legacy advertising on
        // connection; stopping again is a no-op and makes the restart
        // deterministic.
        if (advertiser != null) {
            try {
                advertiser.stopAdvertising(advertiseCallback);
            } catch (RuntimeException ignored) {
                // Nothing to stop.
            }
        }
        if (delayedRestartRunnable != null) {
            handler.removeCallbacks(delayedRestartRunnable);
        }
        delayedRestartRunnable = () -> startAdvertising(true);
        handler.postDelayed(delayedRestartRunnable, RESTART_SETTLE_MS);
    }

    private boolean respond(BluetoothDevice device, int requestId, int status,
            int offset, byte[] response) {
        if (gattServer == null) {
            return false;
        }
        try {
            return gattServer.sendResponse(device, requestId, status, offset, response);
        } catch (RuntimeException error) {
            return false;
        }
    }

    private void finishWithSummary(String reason) {
        if (finished) {
            return;
        }
        finished = true;
        stopping = true;

        if (timeoutRunnable != null) {
            handler.removeCallbacks(timeoutRunnable);
            timeoutRunnable = null;
        }
        if (restartRunnable != null) {
            handler.removeCallbacks(restartRunnable);
            restartRunnable = null;
        }
        if (delayedRestartRunnable != null) {
            handler.removeCallbacks(delayedRestartRunnable);
            delayedRestartRunnable = null;
        }

        stopAdvertising();
        closeServer();

        logEvent("\"event\":\"summary\",\"name\":" + quote(name)
                + ",\"no_service\":" + noService
                + ",\"reads\":" + reads
                + ",\"writes\":" + writes
                + ",\"connections\":" + connections
                + ",\"disconnections\":" + disconnections
                + ",\"readvertisings\":" + readvertisings
                + ",\"reason\":" + quote(reason));
        finish();
    }

    private void stopAdvertising() {
        if (advertiser == null) {
            return;
        }
        try {
            advertiser.stopAdvertising(advertiseCallback);
        } catch (RuntimeException ignored) {
            // Already stopped, or the adapter is gone.
        }
    }

    private void closeServer() {
        if (gattServer == null) {
            return;
        }
        try {
            gattServer.clearServices();
        } catch (RuntimeException ignored) {
            // Server already closed.
        }
        try {
            gattServer.close();
        } catch (RuntimeException ignored) {
            // Server already closed.
        }
        gattServer = null;
        characteristic = null;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (!finished) {
            finished = true;
            stopping = true;
            handler.removeCallbacksAndMessages(null);
            stopAdvertising();
            closeServer();
        }
    }

    private String adapterName() {
        try {
            return adapter == null ? null : adapter.getName();
        } catch (RuntimeException error) {
            return null;
        }
    }

    private String localAddress() {
        try {
            return adapter == null ? "" : adapter.getAddress();
        } catch (RuntimeException error) {
            return "";
        }
    }

    private static String addressOf(BluetoothDevice device) {
        if (device == null) {
            return "";
        }
        try {
            return device.getAddress();
        } catch (RuntimeException error) {
            return "";
        }
    }

    private byte[] valueBytes() {
        return new byte[] {
                (byte) (value & 0xFF),
                (byte) ((value >>> 8) & 0xFF),
                (byte) ((value >>> 16) & 0xFF),
                (byte) ((value >>> 24) & 0xFF),
        };
    }

    private static String advertiseErrorName(int code) {
        switch (code) {
            case AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE:
                return "ADVERTISE_FAILED_DATA_TOO_LARGE";
            case AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS:
                return "ADVERTISE_FAILED_TOO_MANY_ADVERTISERS";
            case AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED:
                return "ADVERTISE_FAILED_ALREADY_STARTED";
            case AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED:
                return "ADVERTISE_FAILED_FEATURE_UNSUPPORTED";
            case AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR:
                return "ADVERTISE_FAILED_INTERNAL_ERROR";
            default:
                return "ADVERTISE_FAILED_UNKNOWN";
        }
    }

    private static String hex32(int number) {
        String hex = Integer.toHexString(number);
        StringBuilder out = new StringBuilder("0x");
        for (int i = hex.length(); i < 8; i++) {
            out.append('0');
        }
        out.append(hex);
        return out.toString();
    }

    private static String quote(String text) {
        if (text == null) {
            return "\"\"";
        }
        StringBuilder out = new StringBuilder(text.length() + 2);
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append("\\u00");
                        out.append(Character.forDigit((c >> 4) & 0xF, 16));
                        out.append(Character.forDigit(c & 0xF, 16));
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        out.append('"');
        return out.toString();
    }

    private void logEvent(String fields) {
        Log.i(TAG, "{" + fields
                + ",\"monotonic_ms\":"
                + (SystemClock.elapsedRealtime() - startElapsed) + "}");
    }
}
