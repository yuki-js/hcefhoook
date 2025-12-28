package app.aoki.yuki.hcefhook.nativehook;

import android.util.Log;

import app.aoki.yuki.hcefhook.core.Constants;

/**
 * Native hook interface for NFC stack manipulation
 * 
 * This class provides native-level access to libnfc-nci.so functions
 * and data structures for bypassing state checks during SENSF_RES injection.
 */
public class NativeHook {
    
    private static final String TAG = "HcefHook.NativeHook";
    
    private static boolean isLoaded = false;
    private static boolean isInitialized = false;
    
    static {
        try {
            System.loadLibrary("hcefhook");
            isLoaded = true;
            Log.i(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e.getMessage());
            isLoaded = false;
        }
    }
    
    /**
     * Check if native library is loaded
     */
    public static boolean isLoaded() {
        return isLoaded;
    }
    
    /**
     * Check if hooks are initialized
     */
    public static boolean isInitialized() {
        return isInitialized;
    }
    
    /**
     * Initialize native hooks
     * Must be called from a process that has libnfc-nci.so loaded (e.g., com.android.nfc)
     */
    public static boolean initialize() {
        if (!isLoaded) {
            Log.e(TAG, "Cannot initialize: native library not loaded");
            return false;
        }
        
        try {
            isInitialized = init();
            if (isInitialized) {
                Log.i(TAG, "Native hooks initialized successfully");
            } else {
                Log.e(TAG, "Native hooks initialization failed");
            }
            return isInitialized;
        } catch (Exception e) {
            Log.e(TAG, "Exception during initialization: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Enable state bypass to allow data transmission in non-active states
     */
    public static void enableStateBypass() {
        if (isLoaded) {
            enableBypass();
            Log.i(TAG, "State bypass enabled");
        }
    }
    
    /**
     * Disable state bypass
     */
    public static void disableStateBypass() {
        if (isLoaded) {
            disableBypass();
            Log.i(TAG, "State bypass disabled");
        }
    }
    
    /**
     * Get current NFA discovery state
     * @return state value or -1 if unavailable
     */
    public static int getDiscoveryState() {
        if (!isLoaded) return -1;
        return getDiscState();
    }
    
    /**
     * Temporarily spoof discovery state to allow data transmission
     * @param state The state to spoof to (use Constants.NFA_DM_RFST_* values)
     * @return true if successful
     */
    public static boolean spoofDiscoveryState(int state) {
        if (!isLoaded) return false;
        return spoofState(state);
    }
    
    /**
     * Spoof state to LISTEN_ACTIVE for SENSF_RES injection
     */
    public static boolean spoofToListenActive() {
        return spoofDiscoveryState(Constants.NFA_DM_RFST_LISTEN_ACTIVE);
    }
    
    /**
     * Build a SENSF_RES frame with the given IDm and PMm
     * @param idm 8-byte IDm
     * @param pmm 8-byte PMm
     * @return SENSF_RES frame or null on error
     */
    public static byte[] createSensfRes(byte[] idm, byte[] pmm) {
        if (!isLoaded) return null;
        if (idm == null || idm.length != 8) return null;
        if (pmm == null || pmm.length != 8) return null;
        return buildSensfRes(idm, pmm);
    }
    
    /**
     * Create SENSF_RES with default test values
     */
    public static byte[] createDefaultSensfRes() {
        return createSensfRes(Constants.DEFAULT_IDM, Constants.DEFAULT_PMM);
    }
    
    /**
     * Get native hook status information
     */
    public static String getStatusInfo() {
        if (!isLoaded) return "Native library not loaded";
        return getInfo();
    }
    
    /**
     * Configure the disc_state offset for the current device
     * This needs to be determined through reverse engineering for each device/Android version
     * @param offset Byte offset of disc_state within nfa_dm_cb structure
     */
    public static void configureDiscStateOffset(int offset) {
        if (isLoaded) {
            setDiscStateOffset(offset);
            Log.i(TAG, "Configured disc_state offset: " + offset);
        }
    }
    
    // Native methods
    private static native boolean init();
    private static native void enableBypass();
    private static native void disableBypass();
    private static native int getDiscState();
    private static native boolean spoofState(int state);
    private static native byte[] buildSensfRes(byte[] idm, byte[] pmm);
    private static native String getInfo();
    private static native void setDiscStateOffset(int offset);
}
