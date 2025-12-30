package app.aoki.yuki.hcefhook.observemode;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.util.Log;

import java.util.List;

/**
 * ObserveMode Manager - Proper implementation without reflection hacks
 * 
 * This class provides a clean interface to Android's Observe Mode functionality
 * introduced in Android 15. It uses the official NfcAdapter API and PollingFrame
 * callbacks.
 * 
 * CRITICAL: This runs in the app process, NOT in com.android.nfc process.
 * The NfcAdapter handles IPC communication with the NFC service automatically.
 * 
 * Design Philosophy:
 * - Use official Android APIs only
 * - No reflection on private methods/fields (per requirement)
 * - Proper callback handling
 * - Clean separation of concerns
 * 
 * Reference: AOSP packages/apps/Nfc/src/com/android/nfc/NfcService.java
 *   Line 2221: public synchronized boolean setObserveMode(boolean enable, String packageName)
 */
public class ObserveModeManager {
    
    private static final String TAG = "ObserveModeManager";
    
    private final Context context;
    private final NfcAdapter nfcAdapter;
    private PollingFrameCallback pollingFrameCallback;
    
    // CRITICAL: Make this public so MainActivity can update it
    // MainActivity is responsible for enabling Observe Mode, NOT this manager
    public boolean isObserveModeEnabled = false;
    
    /**
     * Callback interface for polling frame events
     * 
     * Note: We use Object instead of PollingFrame to avoid dependency on Android 15+ APIs
     * The actual objects will be PollingFrame instances at runtime
     */
    public interface PollingFrameCallback {
        /**
         * Called when a polling frame is detected in Observe Mode
         * 
         * @param frames List of PollingFrame objects (passed as Objects for compatibility)
         */
        void onPollingFramesDetected(List<Object> frames);
    }
    
    /**
     * Initialize ObserveModeManager
     * 
     * @param context Application context
     */
    public ObserveModeManager(Context context) {
        this.context = context.getApplicationContext();
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(this.context);
        
        if (nfcAdapter == null) {
            Log.e(TAG, "NFC is not available on this device");
        } else {
            Log.i(TAG, "ObserveModeManager initialized");
            Log.i(TAG, "NFC enabled: " + nfcAdapter.isEnabled());
        }
    }
    
    /**
     * Set polling frame callback
     * 
     * @param callback Callback to receive polling frame notifications
     */
    public void setPollingFrameCallback(PollingFrameCallback callback) {
        this.pollingFrameCallback = callback;
        Log.i(TAG, "Polling frame callback set");
    }
    

    /**
     * Check if Observe Mode is currently enabled
     * 
     * @return true if Observe Mode is enabled (tracks state set by MainActivity)
     */
    public boolean isObserveModeEnabled() {
        return isObserveModeEnabled;
    }
    

    /**
     * Handle incoming polling frame notification
     * 
     * This method is called when a polling frame is detected.
     * It forwards the frames to the registered callback.
     * 
     * @param frames List of detected polling frames (as Objects for compatibility)
     */
    public void onPollingFramesDetected(List<Object> frames) {
        Log.i(TAG, "Polling frames detected: " + frames.size());
        
        if (pollingFrameCallback != null) {
            pollingFrameCallback.onPollingFramesDetected(frames);
        } else {
            Log.w(TAG, "No callback registered for polling frames");
        }
    }
    

}
