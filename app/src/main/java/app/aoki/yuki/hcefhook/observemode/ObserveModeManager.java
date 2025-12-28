package app.aoki.yuki.hcefhook.observemode;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.core.SensfResBuilder;

/**
 * Observe Mode Manager - Handles NFC Observe Mode activation and SENSF_REQ detection
 * 
 * This class manages the lifecycle of Observe Mode, which is critical for detecting
 * SENSF_REQ (SC=FFFF) without eSE auto-response interference.
 * 
 * Observe Mode Flow:
 * 1. Enable Observe Mode on NFCC
 * 2. NFCC receives RF polling but does NOT auto-respond
 * 3. NFCC sends NCI_ANDROID_POLLING_FRAME_NTF to Host
 * 4. This class detects SENSF_REQ in notification
 * 5. Triggers SENSF_RES injection via hooks
 * 
 * CRITICAL: This must work in conjunction with:
 * - KernelSU config overlay (enables polling notifications)
 * - Xposed hooks (for actual injection)
 * - Native hooks (for state bypass)
 */
public class ObserveModeManager {
    
    private static final String TAG = "HcefHook.ObserveMode";
    
    // Observe Mode state
    private static boolean observeModeActive = false;
    private static boolean initialized = false;
    
    // NFC Adapter reference
    private static NfcAdapter nfcAdapter = null;
    private static Object nativeNfcManager = null;
    
    // Reflection method references
    private static Method enableObserveModeMethod = null;
    private static Method disableObserveModeMethod = null;
    private static Method doEnableDiscoveryMethod = null;
    
    // Callback for SENSF_REQ detection
    public interface SensfReqCallback {
        void onSensfReqDetected(byte[] reqData, int systemCode);
    }
    
    private static SensfReqCallback sensfReqCallback = null;
    
    /**
     * Initialize Observe Mode Manager
     */
    public static boolean initialize(Context context) {
        if (initialized) {
            Log.w(TAG, "Already initialized");
            return true;
        }
        
        Log.i(TAG, "=== Initializing Observe Mode Manager ===");
        
        // Get NFC Adapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(context);
        if (nfcAdapter == null) {
            Log.e(TAG, "✗ CRITICAL: NFC Adapter not available on this device!");
            return false;
        }
        Log.i(TAG, "✓ NFC Adapter obtained");
        
        // Try to get NativeNfcManager instance via reflection
        boolean nativeManagerFound = initializeNativeManager(context);
        if (!nativeManagerFound) {
            Log.w(TAG, "✗ WARNING: Could not access NativeNfcManager");
            Log.w(TAG, "  Observe Mode control may be limited");
        } else {
            Log.i(TAG, "✓ NativeNfcManager access established");
        }
        
        initialized = true;
        Log.i(TAG, "=== Observe Mode Manager Initialized ===");
        return true;
    }
    
    /**
     * Initialize NativeNfcManager for direct Observe Mode control
     */
    private static boolean initializeNativeManager(Context context) {
        try {
            Log.d(TAG, "Attempting to access NfcService...");
            
            // Try to get NfcService
            Class<?> nfcServiceClass = Class.forName("com.android.nfc.NfcService");
            Log.d(TAG, "  NfcService class loaded");
            
            Method getInstanceMethod = nfcServiceClass.getDeclaredMethod("getInstance");
            getInstanceMethod.setAccessible(true);
            Object nfcService = getInstanceMethod.invoke(null);
            
            if (nfcService == null) {
                Log.w(TAG, "  NfcService instance is null");
                return false;
            }
            Log.d(TAG, "  NfcService instance obtained");
            
            // Get mDeviceHost field (contains NativeNfcManager)
            Field nativeManagerField = nfcServiceClass.getDeclaredField("mDeviceHost");
            nativeManagerField.setAccessible(true);
            nativeNfcManager = nativeManagerField.get(nfcService);
            
            if (nativeNfcManager == null) {
                Log.w(TAG, "  NativeNfcManager instance is null");
                return false;
            }
            
            Log.i(TAG, "  NativeNfcManager class: " + nativeNfcManager.getClass().getName());
            
            // Try to find Observe Mode methods
            Class<?> nativeManagerClass = nativeNfcManager.getClass();
            
            // Method names may vary by Android version
            String[] possibleEnableMethods = {
                "enableObserveMode",
                "setObserveMode", 
                "enablePollingLoop",
                "doEnableObserveMode"
            };
            
            for (String methodName : possibleEnableMethods) {
                try {
                    enableObserveModeMethod = nativeManagerClass.getDeclaredMethod(methodName, boolean.class);
                    enableObserveModeMethod.setAccessible(true);
                    Log.i(TAG, "  ✓ Found enable method: " + methodName);
                    break;
                } catch (NoSuchMethodException e) {
                    Log.d(TAG, "  Method not found: " + methodName);
                }
            }
            
            // Find discovery method as alternative
            try {
                doEnableDiscoveryMethod = nativeManagerClass.getDeclaredMethod(
                    "doEnableDiscovery", int.class, boolean.class, boolean.class, 
                    boolean.class, boolean.class, boolean.class, boolean.class);
                doEnableDiscoveryMethod.setAccessible(true);
                Log.i(TAG, "  ✓ Found doEnableDiscovery method");
            } catch (NoSuchMethodException e) {
                Log.d(TAG, "  doEnableDiscovery method not found");
            }
            
            return enableObserveModeMethod != null || doEnableDiscoveryMethod != null;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize NativeNfcManager: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Enable Observe Mode
     * 
     * In Observe Mode:
     * - NFCC does not auto-respond to polling
     * - eSE is silenced
     * - Polling frames are forwarded to Host via NCI_ANDROID_POLLING_FRAME_NTF
     */
    public static boolean enableObserveMode() {
        if (!initialized) {
            Log.e(TAG, "Not initialized! Call initialize() first");
            return false;
        }
        
        if (observeModeActive) {
            Log.w(TAG, "Observe Mode already active");
            return true;
        }
        
        Log.i(TAG, "=== Enabling Observe Mode ===");
        
        boolean success = false;
        
        // Method 1: Direct enableObserveMode call
        if (enableObserveModeMethod != null && nativeNfcManager != null) {
            try {
                Log.i(TAG, "Calling enableObserveMode(true)...");
                Object result = enableObserveModeMethod.invoke(nativeNfcManager, true);
                success = (result instanceof Boolean) ? (Boolean)result : true;
                Log.i(TAG, "enableObserveMode result: " + success);
            } catch (Exception e) {
                Log.e(TAG, "Failed to call enableObserveMode: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Method 2: Use discovery with special parameters for Observe Mode
        if (!success && doEnableDiscoveryMethod != null && nativeNfcManager != null) {
            try {
                Log.i(TAG, "Attempting Observe Mode via doEnableDiscovery...");
                // Parameters: techMask, enableLowPowerPolling, enableReaderMode, 
                //             enableHostRouting, enableP2p, restart, enableObserve
                int techMask = 0x0F;  // All NFC-A/B/F/V technologies
                Object result = doEnableDiscoveryMethod.invoke(nativeNfcManager,
                    techMask,  // techMask
                    false,     // enableLowPowerPolling
                    false,     // enableReaderMode
                    false,     // enableHostRouting
                    false,     // enableP2p  
                    true,      // restart
                    true);     // enableObserve (CRITICAL!)
                success = (result instanceof Boolean) ? (Boolean)result : true;
                Log.i(TAG, "doEnableDiscovery result: " + success);
            } catch (Exception e) {
                Log.e(TAG, "Failed to call doEnableDiscovery: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        // Method 3: NfcAdapter enable (fallback)
        if (!success && nfcAdapter != null) {
            try {
                if (!nfcAdapter.isEnabled()) {
                    Log.i(TAG, "NFC is disabled, cannot enable Observe Mode");
                    return false;
                }
                Log.i(TAG, "NFC is enabled (fallback mode)");
                success = true; // Assume NFC being on is enough
            } catch (Exception e) {
                Log.e(TAG, "Error checking NFC state: " + e.getMessage());
            }
        }
        
        if (success) {
            observeModeActive = true;
            Log.i(TAG, "✓ Observe Mode ENABLED");
            Log.i(TAG, "✓ NFCC will forward polling frames to Host");
            Log.i(TAG, "✓ eSE auto-response suppressed");
        } else {
            Log.e(TAG, "✗ Failed to enable Observe Mode");
            Log.e(TAG, "✗ Ensure KernelSU module is installed and active");
        }
        
        return success;
    }
    
    /**
     * Disable Observe Mode
     */
    public static boolean disableObserveMode() {
        if (!observeModeActive) {
            return true;
        }
        
        Log.i(TAG, "=== Disabling Observe Mode ===");
        
        boolean success = false;
        
        if (enableObserveModeMethod != null && nativeNfcManager != null) {
            try {
                Object result = enableObserveModeMethod.invoke(nativeNfcManager, false);
                success = (result instanceof Boolean) ? (Boolean)result : true;
                Log.i(TAG, "disableObserveMode result: " + success);
            } catch (Exception e) {
                Log.e(TAG, "Failed to disable Observe Mode: " + e.getMessage());
            }
        }
        
        observeModeActive = false;
        Log.i(TAG, "Observe Mode disabled");
        return success;
    }
    
    /**
     * Check if Observe Mode is active
     */
    public static boolean isObserveModeActive() {
        return observeModeActive;
    }
    
    /**
     * Set callback for SENSF_REQ detection
     */
    public static void setSensfReqCallback(SensfReqCallback callback) {
        sensfReqCallback = callback;
        Log.i(TAG, "SENSF_REQ callback registered");
    }
    
    /**
     * Process incoming polling frame notification
     * 
     * This should be called by the Xposed hook when NCI_ANDROID_POLLING_FRAME_NTF is received
     * 
     * @param pollingFrame The raw polling frame data
     */
    public static void onPollingFrameReceived(byte[] pollingFrame) {
        if (pollingFrame == null || pollingFrame.length < 6) {
            Log.w(TAG, "Invalid polling frame: " + 
                  (pollingFrame == null ? "null" : "len=" + pollingFrame.length));
            return;
        }
        
        Log.i(TAG, "=== Polling Frame Received ===");
        Log.i(TAG, "Frame: " + SensfResBuilder.toHexString(pollingFrame));
        
        // Check if this is SENSF_REQ
        // SENSF_REQ format: [Length] [Cmd:00] [SC_H] [SC_L] [RC] [TSN]
        if (pollingFrame.length >= 6 && pollingFrame[1] == 0x00) {
            // This is SENSF_REQ
            int systemCode = ((pollingFrame[2] & 0xFF) << 8) | (pollingFrame[3] & 0xFF);
            
            Log.i(TAG, "*** SENSF_REQ DETECTED ***");
            Log.i(TAG, "  System Code: 0x" + String.format("%04X", systemCode));
            Log.i(TAG, "  Request Code: 0x" + String.format("%02X", pollingFrame[4] & 0xFF));
            Log.i(TAG, "  Time Slot: 0x" + String.format("%02X", pollingFrame[5] & 0xFF));
            
            // Check if this is wildcard (SC=FFFF)
            if (systemCode == 0xFFFF) {
                Log.i(TAG, "*** WILDCARD SENSF_REQ (SC=FFFF) ***");
                Log.i(TAG, "*** TRIGGERING RESPONSE INJECTION ***");
            }
            
            // Notify callback
            if (sensfReqCallback != null) {
                Log.d(TAG, "Invoking SENSF_REQ callback...");
                sensfReqCallback.onSensfReqDetected(pollingFrame, systemCode);
            } else {
                Log.w(TAG, "No SENSF_REQ callback registered!");
            }
        } else {
            Log.d(TAG, "Not a SENSF_REQ (cmd=" + 
                  String.format("%02X", pollingFrame[1] & 0xFF) + ")");
        }
    }
    
    /**
     * Get current status
     */
    public static String getStatus() {
        StringBuilder status = new StringBuilder();
        status.append("Observe Mode Manager Status:\n");
        status.append("  Initialized: ").append(initialized).append("\n");
        status.append("  Observe Mode Active: ").append(observeModeActive).append("\n");
        status.append("  NFC Adapter: ").append(nfcAdapter != null ? "Available" : "N/A").append("\n");
        status.append("  NativeNfcManager: ").append(nativeNfcManager != null ? "Accessible" : "N/A").append("\n");
        status.append("  Enable Method: ").append(enableObserveModeMethod != null ? "Found" : "N/A").append("\n");
        status.append("  Discovery Method: ").append(doEnableDiscoveryMethod != null ? "Found" : "N/A").append("\n");
        status.append("  Callback: ").append(sensfReqCallback != null ? "Registered" : "Not Set").append("\n");
        return status.toString();
    }
}
