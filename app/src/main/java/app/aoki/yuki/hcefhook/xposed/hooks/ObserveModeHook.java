package app.aoki.yuki.hcefhook.xposed.hooks;

import android.content.Context;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.xposed.LogBroadcaster;

/**
 * Hook for controlling NFC Observe Mode
 * 
 * Observe Mode is a vendor-specific NCI command that allows the host to passively
 * observe polling frames from readers without the eSE (Secure Element) responding.
 * This is critical for SENSF_RES injection as it prevents the eSE from sending
 * its own response with a fixed IDm.
 * 
 * Implementation:
 * 1. Hook NfcService.onCreate to capture mDeviceHost (NativeNfcManager)
 * 2. Call setObserveMode() using XposedHelpers (no manual reflection)
 * 3. Expose enableObserveMode()/disableObserveMode() for IPC control
 * 
 * NCI Command sent:
 * - GID: 0x0F (Proprietary/Android)
 * - OID: 0x02 (NCI_ANDROID_PASSIVE_OBSERVE)
 * - Payload: 0x01 (enable) or 0x00 (disable)
 * 
 * Reference: AOSP packages/apps/Nfc/src/com/android/nfc/NfcService.java
 *   Line 2221: public synchronized boolean setObserveMode(boolean enable, String packageName)
 * 
 * NOTE: This code runs in the com.android.nfc process context.
 * Uses XposedHelpers for all method calls (no manual java.lang.reflect.Method)
 */
public class ObserveModeHook {
    
    private static final String TAG = "HcefHook.ObserveMode";
    
    // Captured references from NfcService
    private static Object nativeNfcManager = null;
    
    // Context for logging
    private static LogBroadcaster broadcaster = null;
    
    /**
     * Install Observe Mode hooks
     */
    public static void install(LoadPackageParam lpparam, LogBroadcaster logBroadcaster) {
        broadcaster = logBroadcaster;
        
        try {
            Class<?> nfcServiceClass = XposedHelpers.findClass(
                "com.android.nfc.NfcService", lpparam.classLoader);
            
            // Hook NfcService.onCreate to capture mDeviceHost
            XposedHelpers.findAndHookMethod(
                nfcServiceClass,
                "onCreate",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log(TAG + ": NfcService.onCreate() called");
                        
                        // Get NfcService instance
                        Object nfcService = param.thisObject;
                        
                        // Capture mDeviceHost (NativeNfcManager instance)
                        try {
                            nativeNfcManager = XposedHelpers.getObjectField(nfcService, "mDeviceHost");
                            
                            if (nativeNfcManager != null) {
                                XposedBridge.log(TAG + ": ✓ Captured NativeNfcManager instance");
                                broadcaster.info("NativeNfcManager captured for Observe Mode control");
                            } else {
                                XposedBridge.log(TAG + ": ✗ mDeviceHost is null");
                                broadcaster.warn("Failed to capture NativeNfcManager");
                            }
                        } catch (Exception e) {
                            XposedBridge.log(TAG + ": Failed to get mDeviceHost: " + e.getMessage());
                            broadcaster.error("mDeviceHost capture failed: " + e.getMessage());
                        }
                    }
                }
            );
            
            broadcaster.info("ObserveModeHook installed");
            
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to install hook: " + t.getMessage());
            broadcaster.error("ObserveModeHook installation failed: " + t.getMessage());
        }
    }
    
    /**
     * Enable Observe Mode
     * 
     * @return true if successful, false otherwise
     */
    public static boolean enableObserveMode() {
        XposedBridge.log(TAG + ": enableObserveMode() called");
        
        if (nativeNfcManager == null) {
            XposedBridge.log(TAG + ": ✗ Cannot enable - NativeNfcManager not captured");
            broadcaster.error("Observe Mode enable failed: NativeNfcManager not ready");
            return false;
        }
        
        try {
            // Call setObserveMode(true) using XposedHelpers (no manual reflection)
            // This is the proper AOSP method from DeviceHost interface
            Object result = XposedHelpers.callMethod(nativeNfcManager, "setObserveMode", true);
            
            // Check result
            boolean success = false;
            if (result instanceof Boolean) {
                success = (Boolean) result;
            } else if (result == null) {
                // Some methods return void, assume success if no exception
                success = true;
            } else {
                XposedBridge.log(TAG + ": ✗ Unexpected return type: " + result.getClass().getName());
                broadcaster.warn("Observe Mode returned unexpected type: " + result.getClass().getName());
                success = false;
            }
            
            if (success) {
                XposedBridge.log(TAG + ": ✓✓✓ Observe Mode ENABLED ✓✓✓");
                broadcaster.info("*** Observe Mode ENABLED ***");
                broadcaster.info("NFCC is now in passive observation mode");
                broadcaster.info("eSE will not respond to SENSF_REQ");
            } else {
                XposedBridge.log(TAG + ": ✗ Observe Mode enable failed (method returned false)");
                broadcaster.error("Observe Mode enable failed");
            }
            
            return success;
            
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ✗ Exception enabling Observe Mode: " + e.getMessage());
            e.printStackTrace();
            broadcaster.error("Observe Mode enable exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Disable Observe Mode
     * 
     * @return true if successful, false otherwise
     */
    public static boolean disableObserveMode() {
        XposedBridge.log(TAG + ": disableObserveMode() called");
        
        if (nativeNfcManager == null) {
            XposedBridge.log(TAG + ": ✗ Cannot disable - NativeNfcManager not captured");
            broadcaster.error("Observe Mode disable failed: NativeNfcManager not ready");
            return false;
        }
        
        try {
            // Call setObserveMode(false) using XposedHelpers
            Object result = XposedHelpers.callMethod(nativeNfcManager, "setObserveMode", false);
            
            // Check result
            boolean success = false;
            if (result instanceof Boolean) {
                success = (Boolean) result;
            } else if (result == null) {
                success = true;
            } else {
                XposedBridge.log(TAG + ": ✗ Unexpected return type: " + result.getClass().getName());
                broadcaster.warn("Observe Mode returned unexpected type: " + result.getClass().getName());
                success = false;
            }
            
            if (success) {
                XposedBridge.log(TAG + ": ✓ Observe Mode DISABLED");
                broadcaster.info("Observe Mode DISABLED");
                broadcaster.info("NFCC returned to normal mode");
            } else {
                XposedBridge.log(TAG + ": ✗ Observe Mode disable failed (method returned false)");
                broadcaster.error("Observe Mode disable failed");
            }
            
            return success;
            
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ✗ Exception disabling Observe Mode: " + e.getMessage());
            e.printStackTrace();
            broadcaster.error("Observe Mode disable exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if Observe Mode control is available
     * 
     * @return true if NativeNfcManager was captured
     */
    public static boolean isAvailable() {
        return nativeNfcManager != null;
    }
}
