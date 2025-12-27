package app.aoki.yuki.hcefhook.xposed;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import app.aoki.yuki.hcefhook.core.Constants;

/**
 * Broadcasts log messages and SENSF detection events to the main app
 */
public class LogBroadcaster {
    
    private static final String TAG = "HcefHook.Broadcaster";
    
    private final ContextProvider contextProvider;
    private final String packageName;
    
    public LogBroadcaster(ContextProvider provider, String packageName) {
        this.contextProvider = provider;
        this.packageName = packageName;
    }
    
    /**
     * Log a message to the app
     */
    public void logMessage(String message, int level) {
        Log.d(TAG, "[" + packageName + "] " + message);
        
        Context context = contextProvider.getContext();
        if (context == null) {
            Log.w(TAG, "No context available for broadcast");
            return;
        }
        
        try {
            Intent intent = new Intent(Constants.ACTION_LOG_ENTRY);
            intent.setPackage("app.aoki.yuki.hcefhook");
            intent.putExtra(Constants.EXTRA_LOG_MESSAGE, message);
            intent.putExtra(Constants.EXTRA_LOG_LEVEL, level);
            intent.putExtra(Constants.EXTRA_LOG_TIMESTAMP, System.currentTimeMillis());
            context.sendBroadcast(intent);
        } catch (Exception e) {
            Log.e(TAG, "Failed to broadcast log: " + e.getMessage());
        }
    }
    
    /**
     * Notify about SENSF_REQ detection
     */
    public void notifySensfDetected(byte[] reqData, int systemCode) {
        String msg = "SENSF_REQ detected: SC=0x" + Integer.toHexString(systemCode);
        Log.i(TAG, msg);
        
        Context context = contextProvider.getContext();
        if (context == null) {
            Log.w(TAG, "No context available for SENSF broadcast");
            return;
        }
        
        try {
            Intent intent = new Intent(Constants.ACTION_SENSF_DETECTED);
            intent.setPackage("app.aoki.yuki.hcefhook");
            intent.putExtra(Constants.EXTRA_SENSF_REQ_DATA, reqData);
            intent.putExtra(Constants.EXTRA_SYSTEM_CODE, systemCode);
            context.sendBroadcast(intent);
        } catch (Exception e) {
            Log.e(TAG, "Failed to broadcast SENSF detection: " + e.getMessage());
        }
    }
    
    /**
     * Log info level message
     */
    public void info(String message) {
        logMessage(message, Constants.LOG_INFO);
    }
    
    /**
     * Log debug level message
     */
    public void debug(String message) {
        logMessage(message, Constants.LOG_DEBUG);
    }
    
    /**
     * Log warning level message
     */
    public void warn(String message) {
        logMessage(message, Constants.LOG_WARN);
    }
    
    /**
     * Log error level message
     */
    public void error(String message) {
        logMessage(message, Constants.LOG_ERROR);
    }
}
