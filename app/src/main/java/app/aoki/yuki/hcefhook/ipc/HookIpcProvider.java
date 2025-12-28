package app.aoki.yuki.hcefhook.ipc;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.util.Log;

import java.util.concurrent.ConcurrentHashMap;

/**
 * ContentProvider for IPC between the main app and Xposed hooks
 * 
 * The Xposed hooks run in the context of com.android.nfc process,
 * while this ContentProvider runs in the app's own process.
 * ContentProvider allows cross-process communication.
 * 
 * URI patterns:
 * - content://app.aoki.yuki.hcefhook.ipc/config/{key} - Get/Set configuration
 * - content://app.aoki.yuki.hcefhook.ipc/command/{action} - Execute commands
 * - content://app.aoki.yuki.hcefhook.ipc/status - Get hook status
 */
public class HookIpcProvider extends ContentProvider {
    
    private static final String TAG = "HcefHook.IpcProvider";
    public static final String AUTHORITY = "app.aoki.yuki.hcefhook.ipc";
    
    // URI codes
    private static final int CONFIG = 1;
    private static final int CONFIG_KEY = 2;
    private static final int COMMAND = 3;
    private static final int STATUS = 4;
    private static final int INJECTION_QUEUE = 5;
    
    private static final UriMatcher uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
    
    static {
        uriMatcher.addURI(AUTHORITY, "config", CONFIG);
        uriMatcher.addURI(AUTHORITY, "config/*", CONFIG_KEY);
        uriMatcher.addURI(AUTHORITY, "command/*", COMMAND);
        uriMatcher.addURI(AUTHORITY, "status", STATUS);
        uriMatcher.addURI(AUTHORITY, "injection_queue", INJECTION_QUEUE);
    }
    
    // Configuration storage
    private static final ConcurrentHashMap<String, String> configMap = new ConcurrentHashMap<>();
    
    // Injection queue - frames waiting to be injected by the hook
    private static final ConcurrentHashMap<Long, byte[]> injectionQueue = new ConcurrentHashMap<>();
    private static long injectionCounter = 0;
    
    // Configuration keys
    public static final String KEY_IDM = "idm";
    public static final String KEY_PMM = "pmm";
    public static final String KEY_BYPASS_ENABLED = "bypass_enabled";
    public static final String KEY_AUTO_INJECT = "auto_inject";
    public static final String KEY_DISC_STATE_OFFSET = "disc_state_offset";
    public static final String KEY_HOOK_ACTIVE = "hook_active";
    public static final String KEY_LAST_SENSF_REQ = "last_sensf_req";
    public static final String KEY_INJECTION_COUNT = "injection_count";
    
    @Override
    public boolean onCreate() {
        Log.i(TAG, "onCreate() - IPC Provider created");
        // Initialize default configuration
        configMap.put(KEY_BYPASS_ENABLED, "false");
        configMap.put(KEY_AUTO_INJECT, "false");
        configMap.put(KEY_HOOK_ACTIVE, "false");
        configMap.put(KEY_INJECTION_COUNT, "0");
        Log.d(TAG, "onCreate() - Default configuration initialized");
        return true;
    }
    
    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        
        Log.v(TAG, "query() - URI: " + uri);
        int match = uriMatcher.match(uri);
        MatrixCursor cursor;
        
        switch (match) {
            case CONFIG:
                Log.d(TAG, "query() - Returning all config values");
                // Return all config values
                cursor = new MatrixCursor(new String[]{"key", "value"});
                for (String key : configMap.keySet()) {
                    cursor.addRow(new Object[]{key, configMap.get(key)});
                }
                return cursor;
                
            case CONFIG_KEY:
                // Return specific config value
                String key = uri.getLastPathSegment();
                Log.d(TAG, "query() - Returning config key: " + key);
                cursor = new MatrixCursor(new String[]{"key", "value"});
                String value = configMap.get(key);
                if (value != null) {
                    cursor.addRow(new Object[]{key, value});
                }
                return cursor;
                
            case STATUS:
                Log.d(TAG, "query() - Returning status");
                // Return status information
                cursor = new MatrixCursor(new String[]{"key", "value"});
                cursor.addRow(new Object[]{"hook_active", configMap.getOrDefault(KEY_HOOK_ACTIVE, "false")});
                cursor.addRow(new Object[]{"bypass_enabled", configMap.getOrDefault(KEY_BYPASS_ENABLED, "false")});
                cursor.addRow(new Object[]{"auto_inject", configMap.getOrDefault(KEY_AUTO_INJECT, "false")});
                cursor.addRow(new Object[]{"injection_count", configMap.getOrDefault(KEY_INJECTION_COUNT, "0")});
                cursor.addRow(new Object[]{"pending_injections", String.valueOf(injectionQueue.size())});
                return cursor;
                
            case INJECTION_QUEUE:
                Log.d(TAG, "query() - Returning pending injection (queue size: " + injectionQueue.size() + ")");
                // Return pending injection (for hook to consume)
                cursor = new MatrixCursor(new String[]{"id", "data"});
                if (!injectionQueue.isEmpty()) {
                    Long id = injectionQueue.keySet().iterator().next();
                    byte[] data = injectionQueue.remove(id);
                    if (data != null) {
                        cursor.addRow(new Object[]{id, bytesToHex(data)});
                        Log.i(TAG, "query() - Dequeued injection #" + id);
                    }
                }
                return cursor;
                
            default:
                Log.e(TAG, "query() - Unknown URI: " + uri);
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
    }
    
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        Log.v(TAG, "insert() - URI: " + uri);
        int match = uriMatcher.match(uri);
        
        switch (match) {
            case CONFIG:
            case CONFIG_KEY:
                // Insert/update config value
                String key = values.getAsString("key");
                String value = values.getAsString("value");
                if (key != null && value != null) {
                    configMap.put(key, value);
                    Log.d(TAG, "insert() - Config set: " + key + " = " + value);
                    getContext().getContentResolver().notifyChange(uri, null);
                }
                return uri;
                
            case INJECTION_QUEUE:
                // Queue a frame for injection
                String hexData = values.getAsString("data");
                if (hexData != null) {
                    byte[] data = hexToBytes(hexData);
                    long id = ++injectionCounter;
                    injectionQueue.put(id, data);
                    Log.i(TAG, "insert() - Queued injection #" + id + ": " + hexData);
                    
                    // Increment injection count
                    int count = Integer.parseInt(configMap.getOrDefault(KEY_INJECTION_COUNT, "0"));
                    configMap.put(KEY_INJECTION_COUNT, String.valueOf(count + 1));
                    
                    return Uri.withAppendedPath(uri, String.valueOf(id));
                }
                Log.w(TAG, "insert() - No data provided for injection queue");
                return null;
                
            default:
                Log.e(TAG, "insert() - Unknown URI: " + uri);
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
    }
    
    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // Update is same as insert for config
        insert(uri, values);
        return 1;
    }
    
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        int match = uriMatcher.match(uri);
        
        if (match == INJECTION_QUEUE) {
            // Clear injection queue
            int size = injectionQueue.size();
            injectionQueue.clear();
            return size;
        }
        
        return 0;
    }
    
    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.hcefhook.config";
    }
    
    // Static methods for hook to use
    
    /**
     * Set a configuration value (called from hook context)
     */
    public static void setConfig(String key, String value) {
        configMap.put(key, value);
    }
    
    /**
     * Get a configuration value (called from hook context)
     */
    public static String getConfig(String key) {
        return configMap.get(key);
    }
    
    /**
     * Check if there's a pending injection
     */
    public static boolean hasPendingInjection() {
        return !injectionQueue.isEmpty();
    }
    
    /**
     * Get next pending injection frame
     */
    public static byte[] getNextInjection() {
        if (injectionQueue.isEmpty()) return null;
        Long id = injectionQueue.keySet().iterator().next();
        return injectionQueue.remove(id);
    }
    
    // Utility methods
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
