package app.aoki.yuki.hcefhook.nativehook;

import android.util.Log;

/**
 * Native utility functions for HCE-F Hook
 * 
 * Provides module discovery and process information utilities.
 * Does NOT provide hooking - use Frida for that.
 */
public class NativeUtils {
    
    private static final String TAG = "HcefHook.NativeUtils";
    
    private static boolean isLoaded = false;
    
    static {
        try {
            System.loadLibrary("hcefhook");
            isLoaded = true;
            Log.i(TAG, "Native utilities library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "Native utilities not loaded: " + e.getMessage());
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
     * Check if NFC library is loaded in current process
     */
    public static native boolean isNfcLibraryLoaded();
    
    /**
     * Get name of loaded NFC library
     */
    public static native String getNfcLibraryName();
    
    /**
     * Get base address of NFC library
     */
    public static native long getNfcLibraryBase();
    
    /**
     * Get current process ID
     */
    public static native int getProcessId();
    
    /**
     * Log NFC-related process maps for debugging
     */
    public static native void logProcessMaps();
    
    /**
     * Get status information
     */
    public static native String getStatus();
    
    /**
     * Safe wrapper for isNfcLibraryLoaded
     */
    public static boolean isNfcLibraryLoadedSafe() {
        if (!isLoaded) return false;
        try {
            return isNfcLibraryLoaded();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Safe wrapper for getNfcLibraryName
     */
    public static String getNfcLibraryNameSafe() {
        if (!isLoaded) return "(native lib not loaded)";
        try {
            return getNfcLibraryName();
        } catch (Exception e) {
            return "(error)";
        }
    }
}
