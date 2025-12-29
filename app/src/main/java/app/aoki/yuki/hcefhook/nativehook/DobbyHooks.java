package app.aoki.yuki.hcefhook.nativehook;

import android.util.Log;

/**
 * Native hook coordination interface (Frida-based)
 * 
 * NOTE: Dobby has been replaced with Frida for native hooking.
 * This class provides Java-side coordination and state management.
 * 
 * For actual native hooking, use the Frida script at:
 *   assets/frida/observe_mode_bypass.js
 * 
 * Run with: frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause
 * 
 * IMPORTANT: Native hooks must be installed in the com.android.nfc process,
 * NOT in the hcefhook app package.
 * 
 * Key Hook Targets (from AOSP analysis):
 * - NFA_SendRawFrame @ 0x147100 (mangled: _Z16NFA_SendRawFramePhtt)
 * - nfa_dm_act_send_raw_frame @ 0x14e070 (state validation - KEY BLOCKING POINT)
 * - NFC_SendData @ 0x183240
 * - nfa_dm_cb @ 0x24c0f8 (state variable location)
 * 
 * The primary blocking logic is in nfa_dm_act_send_raw_frame() which checks:
 *   if (disc_state == NFA_DM_RFST_POLL_ACTIVE || disc_state == NFA_DM_RFST_LISTEN_ACTIVE)
 * In Observe Mode, disc_state = DISCOVERY (1), not LISTEN_ACTIVE (5), so TX is blocked.
 */
public class DobbyHooks {
    
    private static final String TAG = "HcefHook.NativeHooks";
    
    // State management (Java-side coordination with Frida)
    private static volatile boolean bypassEnabled = false;
    private static volatile boolean sprayModeEnabled = false;
    private static volatile boolean initialized = false;
    
    // Note: Native library is no longer loaded since Frida handles hooks
    
    /**
     * Check if the system is ready
     * With Frida approach, this checks if coordination is set up
     */
    public static boolean isLoaded() {
        return true; // Frida-based approach doesn't need native library
    }
    
    /**
     * Initialize hook coordination
     * 
     * With Frida, actual hooks are installed externally via frida-server.
     * This method sets up Java-side state management.
     * 
     * @return true (always succeeds as actual hooking is done by Frida)
     */
    public static boolean install() {
        Log.i(TAG, "=== Native Hook Coordination Initialized ===");
        Log.i(TAG, "Implementation: Frida-based (Dobby removed)");
        Log.i(TAG, "Process ID: " + android.os.Process.myPid());
        Log.i(TAG, "");
        Log.i(TAG, "=== Hook Target Symbols ===");
        Log.i(TAG, "NFA_SendRawFrame: 0x147100 (_Z16NFA_SendRawFramePhtt)");
        Log.i(TAG, "nfa_dm_act_send_raw_frame: 0x14e070 (KEY BLOCKING POINT)");
        Log.i(TAG, "NFC_SendData: 0x183240");
        Log.i(TAG, "nfa_dm_cb: 0x24c0f8 (state variable)");
        Log.i(TAG, "");
        Log.i(TAG, "=== Frida Usage ===");
        Log.i(TAG, "Script: assets/frida/observe_mode_bypass.js");
        Log.i(TAG, "Run: frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause");
        Log.i(TAG, "");
        Log.i(TAG, "=== Frida RPC Interface ===");
        Log.i(TAG, "  sendSensfRes(idmHex, pmmHex)");
        Log.i(TAG, "  spraySensfRes(idmHex, pmmHex, count, intervalMs)");
        Log.i(TAG, "  enableBypass() / disableBypass()");
        Log.i(TAG, "  getState() / getInfo()");
        
        initialized = true;
        return true;
    }
    
    /**
     * Check if hook coordination is set up
     */
    public static boolean isInstalled() {
        return initialized;
    }
    
    /**
     * Enable state bypass mode (Java-side flag)
     * 
     * Sets a flag for Xposed hooks coordination.
     * Actual native bypass requires the Frida script.
     */
    public static void enableBypass() {
        bypassEnabled = true;
        Log.i(TAG, "State bypass ENABLED (Java flag)");
        Log.i(TAG, "For native bypass, ensure Frida script is running in com.android.nfc");
    }
    
    /**
     * Disable state bypass mode
     */
    public static void disableBypass() {
        bypassEnabled = false;
        Log.i(TAG, "State bypass DISABLED");
    }
    
    /**
     * Enable spray mode coordination
     * 
     * Sets flags for Java-side coordination.
     * Actual spray requires:
     * 1. Frida script: rpc.exports.spraySensfRes(idm, pmm, 100, 3)
     * 2. Or Java-layer SprayController with IPC
     */
    public static void enableSprayMode() {
        sprayModeEnabled = true;
        bypassEnabled = true;  // Spray requires bypass
        Log.i(TAG, "SPRAY MODE ENABLED (coordination flags set)");
        Log.i(TAG, "For actual spray:");
        Log.i(TAG, "  Frida: rpc.exports.spraySensfRes('1145141919810000', 'FFFFFFFFFFFFFFFF', 100, 3)");
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
        sb.append("Initialized: ").append(initialized ? "YES" : "NO").append("\n");
        sb.append("Bypass Enabled: ").append(bypassEnabled ? "YES" : "NO").append("\n");
        sb.append("Spray Mode: ").append(sprayModeEnabled ? "YES" : "NO").append("\n");
        sb.append("Process ID: ").append(android.os.Process.myPid()).append("\n");
        sb.append("\n");
        sb.append("=== Key Hook Targets ===\n");
        sb.append("NFA_SendRawFrame: 0x147100\n");
        sb.append("nfa_dm_act_send_raw_frame: 0x14e070 (blocks TX)\n");
        sb.append("nfa_dm_cb.disc_state: for state spoofing\n");
        sb.append("\n");
        sb.append("=== Frida Usage ===\n");
        sb.append("Script: assets/frida/observe_mode_bypass.js\n");
        sb.append("Run: frida -U -f com.android.nfc -l observe_mode_bypass.js\n");
        return sb.toString();
    }
    
    /**
     * Log hook status to system log
     */
    public static void logStatus() {
        String status = getStatus();
        Log.i(TAG, "=== Native Hook Status ===");
        for (String line : status.split("\n")) {
            if (!line.isEmpty()) {
                Log.i(TAG, line);
            }
        }
        Log.i(TAG, "========================");
    }
}
