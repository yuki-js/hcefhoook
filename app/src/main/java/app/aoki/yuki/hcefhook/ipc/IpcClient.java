package app.aoki.yuki.hcefhook.ipc;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * Client for accessing HookIpcProvider from hook context
 * 
 * This class is used by Xposed hooks running in com.android.nfc to
 * communicate with the main app. Since hooks run in a different process,
 * we use ContentProvider for IPC.
 */
public class IpcClient {
    
    private static final String TAG = "HcefHook.IpcClient";
    
    private static final Uri CONFIG_URI = Uri.parse("content://" + HookIpcProvider.AUTHORITY + "/config");
    private static final Uri STATUS_URI = Uri.parse("content://" + HookIpcProvider.AUTHORITY + "/status");
    private static final Uri INJECTION_URI = Uri.parse("content://" + HookIpcProvider.AUTHORITY + "/injection_queue");
    
    private final Context context;
    private final ContentResolver resolver;
    
    public IpcClient(Context context) {
        Log.v(TAG, "IpcClient() - Constructor called");
        this.context = context;
        this.resolver = context.getContentResolver();
        Log.d(TAG, "IpcClient() - Initialized with context: " + context.getPackageName());
    }
    
    /**
     * Set a configuration value
     */
    public boolean setConfig(String key, String value) {
        Log.d(TAG, "setConfig() - key=" + key + ", value=" + value);
        try {
            ContentValues values = new ContentValues();
            values.put("key", key);
            values.put("value", value);
            resolver.insert(CONFIG_URI, values);
            Log.v(TAG, "setConfig() - Success");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to set config: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Get a configuration value
     */
    public String getConfig(String key) {
        Log.v(TAG, "getConfig() - key=" + key);
        try {
            Uri uri = Uri.withAppendedPath(CONFIG_URI, key);
            Cursor cursor = resolver.query(uri, null, null, null, null);
            if (cursor != null && cursor.moveToFirst()) {
                int valueIndex = cursor.getColumnIndex("value");
                String value = cursor.getString(valueIndex);
                cursor.close();
                Log.v(TAG, "getConfig() - Found value: " + value);
                return value;
            }
            Log.v(TAG, "getConfig() - No value found");
        } catch (Exception e) {
            Log.e(TAG, "Failed to get config: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Get all configuration values
     */
    public Map<String, String> getAllConfig() {
        Map<String, String> config = new HashMap<>();
        try {
            Cursor cursor = resolver.query(CONFIG_URI, null, null, null, null);
            if (cursor != null) {
                int keyIndex = cursor.getColumnIndex("key");
                int valueIndex = cursor.getColumnIndex("value");
                while (cursor.moveToNext()) {
                    config.put(cursor.getString(keyIndex), cursor.getString(valueIndex));
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get all config: " + e.getMessage());
        }
        return config;
    }
    
    /**
     * Get hook status
     */
    public Map<String, String> getStatus() {
        Map<String, String> status = new HashMap<>();
        try {
            Cursor cursor = resolver.query(STATUS_URI, null, null, null, null);
            if (cursor != null) {
                int keyIndex = cursor.getColumnIndex("key");
                int valueIndex = cursor.getColumnIndex("value");
                while (cursor.moveToNext()) {
                    status.put(cursor.getString(keyIndex), cursor.getString(valueIndex));
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get status: " + e.getMessage());
        }
        return status;
    }
    
    /**
     * Queue a SENSF_RES frame for injection
     */
    public boolean queueInjection(byte[] data) {
        Log.i(TAG, "queueInjection() - Queuing SENSF_RES: " + bytesToHex(data));
        try {
            ContentValues values = new ContentValues();
            values.put("data", bytesToHex(data));
            Uri result = resolver.insert(INJECTION_URI, values);
            boolean success = result != null;
            Log.i(TAG, "queueInjection() - " + (success ? "Success" : "Failed"));
            return success;
        } catch (Exception e) {
            Log.e(TAG, "Failed to queue injection: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Get next pending injection (called from hook)
     */
    public byte[] getNextInjection() {
        try {
            Cursor cursor = resolver.query(INJECTION_URI, null, null, null, null);
            if (cursor != null && cursor.moveToFirst()) {
                int dataIndex = cursor.getColumnIndex("data");
                String hexData = cursor.getString(dataIndex);
                cursor.close();
                return hexToBytes(hexData);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get injection: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Clear injection queue
     */
    public void clearInjectionQueue() {
        try {
            resolver.delete(INJECTION_URI, null, null);
        } catch (Exception e) {
            Log.e(TAG, "Failed to clear injection queue: " + e.getMessage());
        }
    }
    
    /**
     * Mark hook as active (called from hook on initialization)
     */
    public void setHookActive(boolean active) {
        setConfig(HookIpcProvider.KEY_HOOK_ACTIVE, String.valueOf(active));
    }
    
    /**
     * Set bypass enabled state
     */
    public void setBypassEnabled(boolean enabled) {
        setConfig(HookIpcProvider.KEY_BYPASS_ENABLED, String.valueOf(enabled));
    }
    
    /**
     * Check if bypass is enabled
     */
    public boolean isBypassEnabled() {
        String value = getConfig(HookIpcProvider.KEY_BYPASS_ENABLED);
        return "true".equals(value);
    }
    
    /**
     * Set auto-inject enabled state
     */
    public void setAutoInject(boolean enabled) {
        setConfig(HookIpcProvider.KEY_AUTO_INJECT, String.valueOf(enabled));
    }
    
    /**
     * Check if auto-inject is enabled
     */
    public boolean isAutoInjectEnabled() {
        String value = getConfig(HookIpcProvider.KEY_AUTO_INJECT);
        return "true".equals(value);
    }
    
    /**
     * Store last SENSF_REQ data
     */
    public void setLastSensfReq(byte[] data) {
        setConfig(HookIpcProvider.KEY_LAST_SENSF_REQ, bytesToHex(data));
    }
    
    /**
     * Set custom IDm
     */
    public void setIdm(byte[] idm) {
        setConfig(HookIpcProvider.KEY_IDM, bytesToHex(idm));
    }
    
    /**
     * Get custom IDm
     */
    public byte[] getIdm() {
        String hex = getConfig(HookIpcProvider.KEY_IDM);
        return hex != null ? hexToBytes(hex) : null;
    }
    
    /**
     * Set custom PMm
     */
    public void setPmm(byte[] pmm) {
        setConfig(HookIpcProvider.KEY_PMM, bytesToHex(pmm));
    }
    
    /**
     * Get custom PMm
     */
    public byte[] getPmm() {
        String hex = getConfig(HookIpcProvider.KEY_PMM);
        return hex != null ? hexToBytes(hex) : null;
    }
    
    /**
     * Enable Observe Mode
     * Sends command to Xposed hooks to enable NFC Observe Mode
     */
    public void enableObserveMode() {
        Log.i(TAG, "enableObserveMode() - Requesting Observe Mode activation");
        try {
            ContentValues cv = new ContentValues();
            cv.put("action", "ENABLE_OBSERVE_MODE");
            resolver.insert(CONFIG_URI, cv);
            Log.i(TAG, "enableObserveMode() - Command sent successfully");
        } catch (Exception e) {
            Log.e(TAG, "enableObserveMode() - Failed: " + e.getMessage());
        }
    }
    
    /**
     * Disable Observe Mode
     * Sends command to Xposed hooks to disable NFC Observe Mode
     */
    public void disableObserveMode() {
        Log.i(TAG, "disableObserveMode() - Requesting Observe Mode deactivation");
        try {
            ContentValues cv = new ContentValues();
            cv.put("action", "DISABLE_OBSERVE_MODE");
            resolver.insert(CONFIG_URI, cv);
            Log.i(TAG, "disableObserveMode() - Command sent successfully");
        } catch (Exception e) {
            Log.e(TAG, "disableObserveMode() - Failed: " + e.getMessage());
        }
    }
    
    /**
     * Send a raw NFC frame via IPC
     * 
     * This queues the frame for transmission through the Xposed hooks.
     * For actual transmission, the hooks must be active in com.android.nfc.
     * 
     * NOTE: This is for coordination only. Actual raw frame transmission
     * requires Frida script running in com.android.nfc process with 
     * state bypass enabled.
     * 
     * @param data Raw frame bytes (e.g., SENSF_RES)
     * @return true if queued successfully
     */
    public boolean sendRawFrame(byte[] data) {
        Log.d(TAG, "sendRawFrame() - Queuing " + (data != null ? data.length : 0) + " bytes");
        try {
            ContentValues cv = new ContentValues();
            cv.put("action", "SEND_RAW_FRAME");
            cv.put("data", bytesToHex(data));
            cv.put("timestamp", System.currentTimeMillis());
            resolver.insert(INJECTION_URI, cv);
            Log.v(TAG, "sendRawFrame() - Frame queued successfully");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "sendRawFrame() - Failed: " + e.getMessage());
            return false;
        }
    }
    
    // Utility methods
    
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
    
    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return null;
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
