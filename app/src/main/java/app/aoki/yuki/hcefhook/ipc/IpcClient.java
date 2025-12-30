package app.aoki.yuki.hcefhook.ipc;

import android.content.Context;
import android.util.Log;

import app.aoki.yuki.hcefhook.ipc.broadcast.BroadcastIpc;

import java.util.HashMap;
import java.util.Map;

/**
 * IPC Client - Wrapper around BroadcastIpc for compatibility
 * 
 * This class provides a simplified interface for IPC communication
 * using ONLY Broadcast-based IPC (no ContentProvider).
 * 
 * NOTE: This is now just a thin wrapper around BroadcastIpc.
 * For new code, use BroadcastIpc directly.
 */
public class IpcClient {
    
    private static final String TAG = "HcefHook.IpcClient";
    
    private final Context context;
    private final BroadcastIpc broadcastIpc;
    private ResponseHandler responseHandler;
    
    /**
     * Response handler interface for async responses
     */
    public interface ResponseHandler {
        void onResponse(String commandType, Map<String, String> data);
    }
    
    public IpcClient(Context context) {
        Log.d(TAG, "IpcClient() - Using Broadcast IPC only (ContentProvider removed)");
        this.context = context;
        this.broadcastIpc = new BroadcastIpc(context, context.getPackageName());
        
        // Set up command handler to receive responses
        broadcastIpc.setCommandHandler((commandType, data, sourceProcess) -> {
            Log.d(TAG, "Received: " + commandType + " from " + sourceProcess);
            if (responseHandler != null) {
                responseHandler.onResponse(commandType, data);
            }
        });
        
        broadcastIpc.register();
        Log.i(TAG, "IpcClient initialized with Broadcast IPC");
    }
    
    /**
     * Set response handler for async responses
     */
    public void setResponseHandler(ResponseHandler handler) {
        this.responseHandler = handler;
    }
    
    /**
     * Send command to hooks
     */
    public boolean sendCommand(String commandType, Map<String, String> data) {
        try {
            broadcastIpc.sendCommand(commandType, data);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to send command: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Set configuration value (sends CONFIG command)
     */
    public boolean setConfig(String key, String value) {
        Map<String, String> data = new HashMap<>();
        data.put("key", key);
        data.put("value", value);
        return sendCommand("SET_CONFIG", data);
    }
    
    /**
     * Enable auto-inject mode
     */
    public boolean setAutoInject(boolean enabled) {
        return setConfig("auto_inject", String.valueOf(enabled));
    }
    
    /**
     * Enable state bypass mode
     */
    public boolean setBypassEnabled(boolean enabled) {
        return setConfig("bypass_enabled", String.valueOf(enabled));
    }
    
    /**
     * Set hook active status
     */
    public boolean setHookActive(boolean active) {
        return setConfig("hook_active", String.valueOf(active));
    }
    
    /**
     * Request status from hooks
     */
    public boolean requestStatus() {
        return sendCommand("GET_STATUS", null);
    }
    
    /**
     * Send mutual ping to verify connection
     */
    public boolean sendPing() {
        Map<String, String> data = new HashMap<>();
        data.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return sendCommand("PING", data);
    }
    
    /**
     * Queue frame for injection
     */
    public boolean queueFrame(byte[] frame) {
        if (frame == null) return false;
        
        Map<String, String> data = new HashMap<>();
        data.put("frame_hex", bytesToHex(frame));
        data.put("length", String.valueOf(frame.length));
        return sendCommand("SEND_FRAME", data);
    }
    
    /**
     * Unregister IPC client (call in onDestroy)
     */
    public void unregister() {
        if (broadcastIpc != null) {
            broadcastIpc.unregister();
        }
    }
    
    /**
     * Get the underlying BroadcastIpc instance for advanced usage
     */
    public BroadcastIpc getBroadcastIpc() {
        return broadcastIpc;
    }
    
    // Helper methods
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
