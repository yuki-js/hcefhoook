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
            Log.e(TAG, "Failed to load native utilities: " + e.getMessage());
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
    public static boolean isNfcLibraryLoaded() {
        if (!isLoaded) return false;
        try {
            return isNfcLibraryLoaded0();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get name of loaded NFC library
     */
    public static String getNfcLibraryName() {
        if (!isLoaded) return "(native lib not loaded)";
        try {
            return getNfcLibraryName0();
        } catch (Exception e) {
            return "(error)";
        }
    }
    
    /**
     * Get base address of NFC library
     */
    public static long getNfcLibraryBase() {
        if (!isLoaded) return 0;
        try {
            return getNfcLibraryBase0();
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Get current process ID
     */
    public static int getProcessId() {
        if (!isLoaded) return android.os.Process.myPid();
        try {
            return getProcessId0();
        } catch (Exception e) {
            return android.os.Process.myPid();
        }
    }
    
    /**
     * Log NFC-related process maps for debugging
     */
    public static void logProcessMaps() {
        if (!isLoaded) {
            Log.w(TAG, "Cannot log process maps: native lib not loaded");
            return;
        }
        try {
            logProcessMaps0();
        } catch (Exception e) {
            Log.e(TAG, "Error logging process maps: " + e.getMessage());
        }
    }
    
    // Native methods
    private static native boolean isNfcLibraryLoaded0();
    private static native String getNfcLibraryName0();
    private static native long getNfcLibraryBase0();
    private static native int getProcessId0();
    private static native void logProcessMaps0();
}
