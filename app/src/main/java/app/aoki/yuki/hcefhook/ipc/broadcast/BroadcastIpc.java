package app.aoki.yuki.hcefhook.ipc.broadcast;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * Unified Broadcast-based IPC Library
 * 
 * Provides bidirectional communication between MainActivity (app process) and
 * Xposed hooks (com.android.nfc process) using Android Broadcast mechanism.
 * 
 * This replaces the broken ContentProvider-based IPC which cannot receive
 * on the com.android.nfc side.
 * 
 * Architecture:
 * - MainActivity → Xposed: Sends broadcasts, Xposed receives
 * - Xposed → MainActivity: Sends broadcasts, MainActivity receives
 * 
 * Usage:
 * ```java
 * // In MainActivity (app process)
 * BroadcastIpc ipc = new BroadcastIpc(context, "app.aoki.yuki.hcefhook");
 * ipc.setCommandHandler(cmd -> {
 *     // Handle commands from Xposed
 * });
 * ipc.sendCommand("GET_STATUS", null);
 * 
 * // In Xposed hooks (com.android.nfc process)
 * BroadcastIpc ipc = new BroadcastIpc(context, "com.android.nfc");
 * ipc.setCommandHandler(cmd -> {
 *     // Handle commands from MainActivity
 * });
 * ipc.sendResponse("STATUS", statusData);
 * ```
 */
public class BroadcastIpc {
    
    private static final String TAG = "BroadcastIpc";
    
    // Intent actions for bidirectional communication
    private static final String ACTION_COMMAND = "app.aoki.yuki.hcefhook.ipc.COMMAND";
    private static final String ACTION_RESPONSE = "app.aoki.yuki.hcefhook.ipc.RESPONSE";
    private static final String ACTION_EVENT = "app.aoki.yuki.hcefhook.ipc.EVENT";
    private static final String ACTION_PING = "app.aoki.yuki.hcefhook.ipc.PING";
    private static final String ACTION_PONG = "app.aoki.yuki.hcefhook.ipc.PONG";
    
    // Intent extras
    private static final String EXTRA_COMMAND_TYPE = "command_type";
    private static final String EXTRA_DATA = "data";
    private static final String EXTRA_TIMESTAMP = "timestamp";
    private static final String EXTRA_SOURCE_PROCESS = "source_process";
    private static final String EXTRA_PING_ID = "ping_id";
    
    private final Context context;
    private final String processName;
    private final CommandReceiver commandReceiver;
    private CommandHandler commandHandler;
    private PingHandler pingHandler;
    private boolean registered = false;
    
    /**
     * Command handler interface
     */
    public interface CommandHandler {
        /**
         * Handle incoming command/response
         * 
         * @param commandType Command type (e.g., "GET_STATUS", "SEND_FRAME")
         * @param data Command data (can be null)
         * @param sourceProcess Source process name
         */
        void onCommand(String commandType, Map<String, String> data, String sourceProcess);
    }
    
    /**
     * Ping handler interface for connection verification
     */
    public interface PingHandler {
        /**
         * Handle ping received (PONG is sent automatically)
         * 
         * @param pingId Ping identifier
         * @param sourceProcess Source process name
         */
        void onPingReceived(String pingId, String sourceProcess);
        
        /**
         * Handle pong received (response to our ping)
         * 
         * @param pingId Ping identifier
         * @param sourceProcess Source process name
         * @param latencyMs Latency in milliseconds
         */
        void onPongReceived(String pingId, String sourceProcess, long latencyMs);
    }
    
    /**
     * Create BroadcastIpc instance
     * 
     * @param context Application/service context
     * @param processName Current process name (for logging)
     */
    public BroadcastIpc(Context context, String processName) {
        this.context = context.getApplicationContext();
        this.processName = processName;
        this.commandReceiver = new CommandReceiver();
    }
    
    /**
     * Set command handler
     * 
     * @param handler Handler for incoming commands
     */
    public void setCommandHandler(CommandHandler handler) {
        this.commandHandler = handler;
    }
    
    /**
     * Set ping handler for connection verification
     * 
     * @param handler Handler for ping/pong events
     */
    public void setPingHandler(PingHandler handler) {
        this.pingHandler = handler;
    }
    
    /**
     * Register broadcast receiver
     * 
     * Call this in onCreate() or after setting command handler
     */
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    public void register() {
        if (registered) {
            Log.w(TAG, "[" + processName + "] Already registered");
            return;
        }
        
        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_COMMAND);
        filter.addAction(ACTION_RESPONSE);
        filter.addAction(ACTION_EVENT);
        filter.addAction(ACTION_PING);
        filter.addAction(ACTION_PONG);
        
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(commandReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                context.registerReceiver(commandReceiver, filter);
            }
            registered = true;
            Log.i(TAG, "[" + processName + "] BroadcastIpc registered");
        } catch (Exception e) {
            Log.e(TAG, "[" + processName + "] Failed to register receiver: " + e.getMessage());
        }
    }
    
    /**
     * Unregister broadcast receiver
     * 
     * Call this in onDestroy()
     */
    public void unregister() {
        if (!registered) {
            return;
        }
        
        try {
            context.unregisterReceiver(commandReceiver);
            registered = false;
            Log.i(TAG, "[" + processName + "] BroadcastIpc unregistered");
        } catch (Exception e) {
            Log.e(TAG, "[" + processName + "] Failed to unregister receiver: " + e.getMessage());
        }
    }
    
    /**
     * Send command to other process
     * 
     * @param commandType Command type
     * @param data Command data (can be null)
     */
    public void sendCommand(String commandType, Map<String, String> data) {
        sendBroadcast(ACTION_COMMAND, commandType, data);
    }
    
    /**
     * Send response to other process
     * 
     * @param commandType Response type
     * @param data Response data (can be null)
     */
    public void sendResponse(String commandType, Map<String, String> data) {
        sendBroadcast(ACTION_RESPONSE, commandType, data);
    }
    
    /**
     * Send event to other process
     * 
     * @param eventType Event type
     * @param data Event data (can be null)
     */
    public void sendEvent(String eventType, Map<String, String> data) {
        sendBroadcast(ACTION_EVENT, eventType, data);
    }
    
    /**
     * Send ping to verify connection (Mutual Ping)
     * 
     * The other process will automatically respond with PONG.
     * 
     * @param pingId Unique ping identifier (use timestamp or UUID)
     * @return true if ping was sent
     */
    public boolean sendPing(String pingId) {
        try {
            Intent intent = new Intent(ACTION_PING);
            intent.setPackage("app.aoki.yuki.hcefhook");
            intent.putExtra(EXTRA_PING_ID, pingId);
            intent.putExtra(EXTRA_SOURCE_PROCESS, processName);
            intent.putExtra(EXTRA_TIMESTAMP, System.currentTimeMillis());
            
            context.sendBroadcast(intent);
            Log.d(TAG, "[" + processName + "] Sent PING: " + pingId);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "[" + processName + "] Failed to send ping: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Internal method to send pong response
     */
    private void sendPong(String pingId, String targetProcess) {
        try {
            Intent intent = new Intent(ACTION_PONG);
            intent.setPackage("app.aoki.yuki.hcefhook");
            intent.putExtra(EXTRA_PING_ID, pingId);
            intent.putExtra(EXTRA_SOURCE_PROCESS, processName);
            intent.putExtra(EXTRA_TIMESTAMP, System.currentTimeMillis());
            
            context.sendBroadcast(intent);
            Log.d(TAG, "[" + processName + "] Sent PONG: " + pingId + " to " + targetProcess);
        } catch (Exception e) {
            Log.e(TAG, "[" + processName + "] Failed to send pong: " + e.getMessage());
        }
    }
    
    /**
     * Internal broadcast sender
     */
    private void sendBroadcast(String action, String commandType, Map<String, String> data) {
        try {
            Intent intent = new Intent(action);
            intent.setPackage("app.aoki.yuki.hcefhook");
            intent.putExtra(EXTRA_COMMAND_TYPE, commandType);
            intent.putExtra(EXTRA_SOURCE_PROCESS, processName);
            intent.putExtra(EXTRA_TIMESTAMP, System.currentTimeMillis());
            
            if (data != null) {
                // Convert Map to Bundle-compatible format
                for (Map.Entry<String, String> entry : data.entrySet()) {
                    intent.putExtra(entry.getKey(), entry.getValue());
                }
            }
            
            context.sendBroadcast(intent);
            Log.d(TAG, "[" + processName + "] Sent broadcast: " + action + " / " + commandType);
        } catch (Exception e) {
            Log.e(TAG, "[" + processName + "] Failed to send broadcast: " + e.getMessage());
        }
    }
    
    /**
     * Broadcast receiver for commands/responses
     */
    private class CommandReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || intent.getAction() == null) {
                return;
            }
            
            String action = intent.getAction();
            
            // Handle PING/PONG separately
            if (ACTION_PING.equals(action)) {
                handlePing(intent);
                return;
            } else if (ACTION_PONG.equals(action)) {
                handlePong(intent);
                return;
            }
            
            // Handle regular commands/responses
            String commandType = intent.getStringExtra(EXTRA_COMMAND_TYPE);
            String sourceProcess = intent.getStringExtra(EXTRA_SOURCE_PROCESS);
            
            if (commandType == null) {
                Log.w(TAG, "[" + processName + "] Received broadcast with no command type");
                return;
            }
            
            // Extract data from intent extras
            Map<String, String> data = new HashMap<>();
            for (String key : intent.getExtras().keySet()) {
                if (!key.equals(EXTRA_COMMAND_TYPE) && 
                    !key.equals(EXTRA_SOURCE_PROCESS) && 
                    !key.equals(EXTRA_TIMESTAMP) &&
                    !key.equals(EXTRA_PING_ID)) {
                    Object value = intent.getExtras().get(key);
                    if (value instanceof String) {
                        data.put(key, (String) value);
                    }
                }
            }
            
            Log.d(TAG, "[" + processName + "] Received: " + action + " / " + commandType + 
                      " from " + sourceProcess);
            
            if (commandHandler != null) {
                try {
                    commandHandler.onCommand(commandType, data, sourceProcess);
                } catch (Exception e) {
                    Log.e(TAG, "[" + processName + "] Command handler error: " + e.getMessage());
                }
            } else {
                Log.w(TAG, "[" + processName + "] No command handler registered");
            }
        }
        
        private void handlePing(Intent intent) {
            String pingId = intent.getStringExtra(EXTRA_PING_ID);
            String sourceProcess = intent.getStringExtra(EXTRA_SOURCE_PROCESS);
            
            Log.d(TAG, "[" + processName + "] Received PING: " + pingId + " from " + sourceProcess);
            
            // Automatically send PONG
            sendPong(pingId, sourceProcess);
            
            // Notify ping handler if registered
            if (pingHandler != null) {
                try {
                    pingHandler.onPingReceived(pingId, sourceProcess);
                } catch (Exception e) {
                    Log.e(TAG, "[" + processName + "] Ping handler error: " + e.getMessage());
                }
            }
        }
        
        private void handlePong(Intent intent) {
            String pingId = intent.getStringExtra(EXTRA_PING_ID);
            String sourceProcess = intent.getStringExtra(EXTRA_SOURCE_PROCESS);
            long pongTime = System.currentTimeMillis();
            long pingTime = intent.getLongExtra(EXTRA_TIMESTAMP, pongTime);
            long latency = pongTime - pingTime;
            
            Log.d(TAG, "[" + processName + "] Received PONG: " + pingId + " from " + sourceProcess + 
                      " (latency: " + latency + "ms)");
            
            // Notify ping handler if registered
            if (pingHandler != null) {
                try {
                    pingHandler.onPongReceived(pingId, sourceProcess, latency);
                } catch (Exception e) {
                    Log.e(TAG, "[" + processName + "] Pong handler error: " + e.getMessage());
                }
            }
        }
    }
}
