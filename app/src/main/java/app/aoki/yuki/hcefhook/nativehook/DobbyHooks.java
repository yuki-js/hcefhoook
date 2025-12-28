package app.aoki.yuki.hcefhook.nativehook;

import android.util.Log;

/**
 * Dobby-based native hook interface for NFC stack manipulation
 * 
 * This class provides Dobby framework-based runtime hooking of libnfc-nci.so
 * functions. Unlike the basic NativeHook class, this uses Dobby for true
 * inline hooking, allowing interception and modification of function behavior.
 * 
 * CRITICAL: This must be loaded and initialized in the android.nfc process,
 * NOT in the hcefhook app package. The Xposed module handles this injection.
 * 
 * Key capabilities:
 * - Hook nfa_dm_is_data_exchange_allowed() to bypass state checks
 * - Hook nfa_dm_act_send_raw_frame() to enable TX in Observe Mode
 * - Hook NFC_SendData() for spray strategy implementation
 * - Enable continuous SENSF_RES transmission (spray mode)
 */
public class DobbyHooks {
    
    private static final String TAG = "HcefHook.DobbyHooks";
    
    private static boolean isLoaded = false;
    private static boolean isInitialized = false;
    
    static {
        try {
            System.loadLibrary("hcefhook");
            isLoaded = true;
            Log.i(TAG, "Native library with Dobby loaded successfully");
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
     * Install all Dobby hooks
     * 
     * MUST be called from android.nfc process after libnfc-nci.so is loaded.
     * This is typically done in the Xposed module's initialization.
     * 
     * @return true if hooks were successfully installed
     */
    public static boolean install() {
        if (!isLoaded) {
            Log.e(TAG, "Cannot install hooks: native library not loaded");
            return false;
        }
        
        if (isInitialized) {
            Log.w(TAG, "Hooks already installed");
            return true;
        }
        
        try {
            boolean success = installHooks();
            isInitialized = success;
            
            if (success) {
                Log.i(TAG, "Dobby hooks installed successfully");
                Log.i(TAG, "Process: " + android.os.Process.myPid());
                Log.i(TAG, getStatus());
            } else {
                Log.e(TAG, "Failed to install Dobby hooks");
            }
            
            return success;
        } catch (Exception e) {
            Log.e(TAG, "Exception during hook installation: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Check if hooks are installed
     */
    public static boolean isInstalled() {
        if (!isLoaded) return false;
        try {
            return isInstalled0();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Enable state bypass mode
     * 
     * When enabled, state checks in nfa_dm_is_data_exchange_allowed() are
     * bypassed, allowing data transmission in Observe Mode (DISCOVERY state).
     */
    public static void enableBypass() {
        if (isLoaded && isInitialized) {
            enableBypass0();
            Log.i(TAG, "State bypass ENABLED");
        } else {
            Log.w(TAG, "Cannot enable bypass: hooks not installed");
        }
    }
    
    /**
     * Disable state bypass mode
     */
    public static void disableBypass() {
        if (isLoaded && isInitialized) {
            disableBypass0();
            Log.i(TAG, "State bypass DISABLED");
        }
    }
    
    /**
     * Enable spray mode for continuous SENSF_REQ response
     * 
     * Spray Strategy: Continuously respond to SENSF_REQ to increase likelihood
     * of successful collision-free reception by the reader, compensating for
     * the inability to meet the 2.4ms FeliCa timing constraint in software.
     * 
     * When enabled:
     * - Bypass mode is automatically enabled
     * - SENSF_RES will be transmitted repeatedly
     * - Connection stability is improved through probabilistic timing
     */
    public static void enableSprayMode() {
        if (isLoaded && isInitialized) {
            enableSprayMode0();
            Log.i(TAG, "SPRAY MODE ENABLED - continuous SENSF_RES transmission");
        } else {
            Log.w(TAG, "Cannot enable spray mode: hooks not installed");
        }
    }
    
    /**
     * Disable spray mode
     */
    public static void disableSprayMode() {
        if (isLoaded && isInitialized) {
            disableSprayMode0();
            Log.i(TAG, "SPRAY MODE DISABLED");
        }
    }
    
    /**
     * Check if bypass mode is currently enabled
     */
    public static boolean isBypassEnabled() {
        if (!isLoaded || !isInitialized) return false;
        try {
            return isBypassEnabled0();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check if spray mode is currently enabled
     */
    public static boolean isSprayModeEnabled() {
        if (!isLoaded || !isInitialized) return false;
        try {
            return isSprayModeEnabled0();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get detailed status information about installed hooks
     */
    public static String getStatus() {
        if (!isLoaded) {
            return "Native library not loaded";
        }
        if (!isInitialized) {
            return "Hooks not installed";
        }
        
        try {
            return getStatus0();
        } catch (Exception e) {
            return "Error getting status: " + e.getMessage();
        }
    }
    
    /**
     * Log hook status to system log
     */
    public static void logStatus() {
        String status = getStatus();
        Log.i(TAG, "=== Dobby Hook Status ===");
        for (String line : status.split("\n")) {
            Log.i(TAG, line);
        }
        Log.i(TAG, "========================");
    }
    
    // Native methods
    private static native boolean installHooks();
    private static native void enableBypass0();
    private static native void disableBypass0();
    private static native void enableSprayMode0();
    private static native void disableSprayMode0();
    private static native boolean isInstalled0();
    private static native boolean isBypassEnabled0();
    private static native boolean isSprayModeEnabled0();
    private static native String getStatus0();
}
