package app.aoki.yuki.hcefhook.nativehook;

import android.util.Log;

/**
 * Native hook interface for NFC stack manipulation
 * 
 * NOTE: Dobby has been replaced with Frida for hooking.
 * This class now provides a pure Java fallback implementation and
 * coordination with Frida scripts for native hooking.
 * 
 * For actual native hooking, use the Frida script at:
 *   assets/frida/observe_mode_bypass.js
 * 
 * Run with: frida -U -f com.android.nfc -l observe_mode_bypass.js
 * 
 * CRITICAL: Native hooks must be installed in the com.android.nfc process,
 * NOT in the hcefhook app package. Use Frida for this purpose.
 * 
 * Key capabilities (via Frida):
 * - Hook NFC_SendData() to monitor/intercept raw frame transmission
 * - Hook nfa_dm_act_send_raw_frame() to enable TX in Observe Mode
 * - Direct nfa_dm_cb state manipulation for state bypass
 * - Enable continuous SENSF_RES transmission (spray mode)
 */
public class DobbyHooks {
    
    private static final String TAG = "HcefHook.NativeHooks";
    
    // State management (pure Java - for coordination with Frida)
    private static volatile boolean bypassEnabled = false;
    private static volatile boolean sprayModeEnabled = false;
    private static volatile boolean hooksInstalled = false;
    
    /**
     * Check if native library is loaded
     * Note: With Frida approach, this always returns true as hooks are external
     */
    public static boolean isLoaded() {
        // Frida-based hooking doesn't require a native library in the app
        return true;
    }
    
    /**
     * Install hooks (placeholder for Frida-based approach)
     * 
     * With Frida, hooks are installed externally via frida-server.
     * This method marks the system as ready for coordination.
     * 
     * @return true (always succeeds as actual hooking is done by Frida)
     */
    public static boolean install() {
        Log.i(TAG, "=== Native Hook Coordination Initialized ===");
        Log.i(TAG, "Actual native hooks should be installed via Frida");
        Log.i(TAG, "Run: frida -U -f com.android.nfc -l observe_mode_bypass.js");
        Log.i(TAG, "Process: " + android.os.Process.myPid());
        
        hooksInstalled = true;
        return true;
    }
    
    /**
     * Check if hooks are installed
     */
    public static boolean isInstalled() {
        return hooksInstalled;
    }
    
    /**
     * Enable state bypass mode
     * 
     * Sets a flag that Xposed hooks can check.
     * Actual native bypass requires Frida script.
     */
    public static void enableBypass() {
        bypassEnabled = true;
        Log.i(TAG, "State bypass ENABLED (flag set)");
        Log.i(TAG, "For native bypass, ensure Frida script is running");
    }
    
    /**
     * Disable state bypass mode
     */
    public static void disableBypass() {
        bypassEnabled = false;
        Log.i(TAG, "State bypass DISABLED");
    }
    
    /**
     * Enable spray mode for continuous SENSF_REQ response
     * 
     * Sets flags for Xposed coordination.
     * Actual spray requires either:
     * 1. Frida script: rpc.exports.spraySensfRes(idm, pmm, 100, 3)
     * 2. Java-layer SprayController
     */
    public static void enableSprayMode() {
        sprayModeEnabled = true;
        bypassEnabled = true;  // Spray mode requires bypass
        Log.i(TAG, "SPRAY MODE ENABLED");
        Log.i(TAG, "Use Frida RPC or SprayController for actual spray");
    }
    
    /**
     * Disable spray mode
     */
    public static void disableSprayMode() {
        sprayModeEnabled = false;
        Log.i(TAG, "SPRAY MODE DISABLED");
    }
    
    /**
     * Check if bypass mode is currently enabled
     */
    public static boolean isBypassEnabled() {
        return bypassEnabled;
    }
    
    /**
     * Check if spray mode is currently enabled
     */
    public static boolean isSprayModeEnabled() {
        return sprayModeEnabled;
    }
    
    /**
     * Get detailed status information
     */
    public static String getStatus() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Native Hook Status ===\n");
        sb.append("Implementation: Frida-based (Dobby removed)\n");
        sb.append("Hooks Initialized: ").append(hooksInstalled ? "YES" : "NO").append("\n");
        sb.append("Bypass Enabled: ").append(bypassEnabled ? "YES" : "NO").append("\n");
        sb.append("Spray Mode: ").append(sprayModeEnabled ? "YES" : "NO").append("\n");
        sb.append("Process ID: ").append(android.os.Process.myPid()).append("\n");
        sb.append("\n");
        sb.append("=== Frida Usage ===\n");
        sb.append("Script: assets/frida/observe_mode_bypass.js\n");
        sb.append("Run: frida -U -f com.android.nfc -l observe_mode_bypass.js\n");
        sb.append("RPC: sendSensfRes(idm, pmm), spraySensfRes(...)\n");
        return sb.toString();
    }
    
    /**
     * Log hook status to system log
     */
    public static void logStatus() {
        String status = getStatus();
        Log.i(TAG, "=== Native Hook Status ===");
        for (String line : status.split("\n")) {
            Log.i(TAG, line);
        }
        Log.i(TAG, "========================");
    }
}
