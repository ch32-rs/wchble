package dev.wchble.o2adv;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertisingSet;
import android.bluetooth.le.AdvertisingSetCallback;
import android.bluetooth.le.AdvertisingSetParameters;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

/**
 * Controlled O2 advertising source.
 *
 * Modes: "scannable" (ADV_SCAN_IND with a scan response), "non-scannable"
 * (ADV_NONCONN_IND) and "wrong-marker" (scannable, different ADV marker).
 * Advertising data always carries manufacturer 0xFFFF + "O2ADV"/"O2ADX" + 0x01
 * and the scannable response carries 0xFFFF + "O2RSP" + 0x01.
 */
public final class AdvActivity extends Activity {
    private static final String TAG = "WCHBLE";
    private static final int COMPANY_ID = 0xFFFF;
    private static final int MODE_SCANNABLE = 0;
    private static final int MODE_NON_SCANNABLE = 1;
    private static final int MODE_WRONG_MARKER = 2;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private BluetoothLeAdvertiser advertiser;
    private AdvertisingSet activeSet;
    private boolean stopLogged;

    private final AdvertisingSetCallback callback = new AdvertisingSetCallback() {
        @Override
        public void onAdvertisingSetStarted(AdvertisingSet set, int txPower, int status) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                log("{\"event\":\"error\",\"stage\":\"started\",\"status\":" + status + "}");
                return;
            }
            activeSet = set;
            log("{\"event\":\"started\",\"tx_power\":" + txPower + "}");
        }

        @Override
        public void onAdvertisingEnabled(AdvertisingSet set, boolean enable, int status) {
            if (enable && status == AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                log("{\"event\":\"advertising\"}");
            } else {
                log("{\"event\":\"enabled\",\"enable\":" + enable + ",\"status\":" + status + "}");
            }
        }

        @Override
        public void onAdvertisingDataSet(AdvertisingSet set, int status) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                log("{\"event\":\"error\",\"stage\":\"adv-data\",\"status\":" + status + "}");
            }
        }

        @Override
        public void onScanResponseDataSet(AdvertisingSet set, int status) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                log("{\"event\":\"error\",\"stage\":\"scan-rsp-data\",\"status\":" + status + "}");
            }
        }

        @Override
        public void onAdvertisingSetStopped(AdvertisingSet set) {
            if (!stopLogged) {
                stopLogged = true;
                log("{\"event\":\"stopped\"}");
            }
        }
    };

    private static final String[] PERMISSIONS = {
            Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT };

    private String modeName;
    private int seconds;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        modeName = getIntent().getStringExtra("mode");
        if (modeName == null) {
            modeName = "scannable";
        }
        seconds = getIntent().getIntExtra("seconds", 90);
        log("{\"event\":\"config\",\"mode\":\"" + modeName + "\",\"seconds\":" + seconds + "}");
        if (missingPermission() != null) {
            // Some vendor ROMs refuse `pm grant` from the shell. Ask once; the
            // grant persists for later installs of this signing identity.
            log("{\"event\":\"permission-request\"}");
            requestPermissions(PERMISSIONS, 1);
            return;
        }
        start();
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        String missing = missingPermission();
        if (missing != null) {
            log("{\"event\":\"error\",\"reason\":\"missing " + missing + "\"}");
            return;
        }
        start();
    }

    private String missingPermission() {
        for (String permission : PERMISSIONS) {
            if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                return permission;
            }
        }
        return null;
    }

    private void start() {
        int mode;
        if ("non-scannable".equals(modeName)) {
            mode = MODE_NON_SCANNABLE;
        } else if ("wrong-marker".equals(modeName)) {
            mode = MODE_WRONG_MARKER;
        } else if ("scannable".equals(modeName)) {
            mode = MODE_SCANNABLE;
        } else {
            log("{\"event\":\"error\",\"reason\":\"unknown mode\"}");
            return;
        }
        BluetoothManager manager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            log("{\"event\":\"error\",\"reason\":\"adapter disabled\"}");
            return;
        }
        advertiser = adapter.getBluetoothLeAdvertiser();
        if (advertiser == null) {
            log("{\"event\":\"error\",\"reason\":\"no LE advertiser\"}");
            return;
        }

        boolean scannable = mode != MODE_NON_SCANNABLE;
        byte[] advMarker = ascii(mode == MODE_WRONG_MARKER ? "O2ADX" : "O2ADV");
        byte[] rspMarker = ascii("O2RSP");
        AdvertisingSetParameters params = new AdvertisingSetParameters.Builder()
                .setLegacyMode(true)
                .setConnectable(false)
                .setScannable(scannable)
                .setPrimaryPhy(BluetoothDevice.PHY_LE_1M)
                .setInterval(0xA0)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_MEDIUM)
                .build();
        AdvertiseData advData = data(advMarker);
        AdvertiseData scanResponse = scannable ? data(rspMarker) : null;
        log("{\"event\":\"ad-bytes\",\"adv\":\"" + adHex(advMarker) + "\",\"rsp\":\""
                + (scanResponse == null ? "" : adHex(rspMarker)) + "\"}");

        try {
            // duration is in 10 ms units; 0 would mean "until stopped".
            advertiser.startAdvertisingSet(params, advData, scanResponse, null, null,
                    Math.max(1, seconds * 100), 0, callback);
        } catch (RuntimeException error) {
            log("{\"event\":\"error\",\"reason\":\"" + escape(error.toString()) + "\"}");
        }
        // Keep the process alive for the whole run even if advertising ends
        // early, then exit so the runner never leaves a stale advertiser.
        handler.postDelayed(
                () -> {
                    if (advertiser != null && activeSet != null) {
                        try {
                            advertiser.stopAdvertisingSet(callback);
                        } catch (RuntimeException error) {
                            log("{\"event\":\"error\",\"stage\":\"stop\"}");
                        }
                    }
                    finish();
                },
                (seconds + 10) * 1000L);
    }

    private static AdvertiseData data(byte[] marker) {
        return new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addManufacturerData(COMPANY_ID, marker)
                .build();
    }

    private static byte[] ascii(String text) {
        byte[] out = new byte[text.length() + 1];
        for (int i = 0; i < text.length(); i++) {
            out[i] = (byte) text.charAt(i);
        }
        out[text.length()] = 0x01;
        return out;
    }

    /** Manufacturer AD element on air: len, 0xFF, company LE, marker. */
    private static String adHex(byte[] marker) {
        StringBuilder out = new StringBuilder();
        appendHex(out, 1 + 2 + marker.length);
        appendHex(out, 0xFF);
        appendHex(out, COMPANY_ID & 0xFF);
        appendHex(out, (COMPANY_ID >> 8) & 0xFF);
        for (byte b : marker) {
            appendHex(out, b & 0xFF);
        }
        return out.toString();
    }

    private static void appendHex(StringBuilder out, int value) {
        if (out.length() > 0) {
            out.append(' ');
        }
        out.append(Character.forDigit((value >> 4) & 0xF, 16));
        out.append(Character.forDigit(value & 0xF, 16));
    }

    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void log(String json) {
        Log.i(TAG, json);
    }
}
