package app.aoki.yuki.hcefhook.core;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * BroadcastReceiver for receiving log entries from Xposed hooks
 */
public class LogReceiver extends BroadcastReceiver {
    
    private static final String TAG = "HcefHook.LogReceiver";
    
    private static LogCallback callback;
    
    public interface LogCallback {
        void onLogReceived(String message, int level, long timestamp);
        void onSensfDetected(byte[] reqData, int systemCode);
    }
    
    public static void setCallback(LogCallback cb) {
        callback = cb;
    }
    
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) {
            return;
        }
        
        String action = intent.getAction();
        
        if (Constants.ACTION_LOG_ENTRY.equals(action)) {
            String message = intent.getStringExtra(Constants.EXTRA_LOG_MESSAGE);
            int level = intent.getIntExtra(Constants.EXTRA_LOG_LEVEL, Constants.LOG_INFO);
            long timestamp = intent.getLongExtra(Constants.EXTRA_LOG_TIMESTAMP, System.currentTimeMillis());
            
            Log.d(TAG, "Log received: " + message);
            
            if (callback != null) {
                callback.onLogReceived(message, level, timestamp);
            }
        } else if (Constants.ACTION_SENSF_DETECTED.equals(action)) {
            byte[] reqData = intent.getByteArrayExtra(Constants.EXTRA_SENSF_REQ_DATA);
            int systemCode = intent.getIntExtra(Constants.EXTRA_SYSTEM_CODE, 0);
            
            Log.d(TAG, "SENSF_REQ detected: SC=0x" + Integer.toHexString(systemCode));
            
            if (callback != null) {
                callback.onSensfDetected(reqData, systemCode);
            }
        }
    }
}
