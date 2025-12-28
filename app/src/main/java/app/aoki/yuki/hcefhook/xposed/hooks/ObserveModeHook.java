package app.aoki.yuki.hcefhook.xposed.hooks;

import android.content.Context;

import java.lang.reflect.Method;

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
 * 2. Find setObserveMode() method via reflection
 * 3. Expose enableObserveMode()/disableObserveMode() for IPC control
 * 
 * NCI Command sent:
 * - GID: 0x0F (Proprietary/Android)
 * - OID: 0x02 (NCI_ANDROID_PASSIVE_OBSERVE)
 * - Payload: 0x01 (enable) or 0x00 (disable)
 * 
 * Reference: AOSP packages/apps/Nfc/src/com/android/nfc/dhimpl/NativeNfcManager.cpp
 * 
 * NOTE: This code runs in the com.android.nfc process context.
 */
public class ObserveModeHook {
    
    private static final String TAG = "HcefHook.ObserveMode";
    
    // Captured references from NfcService
    private static Object nativeNfcManager = null;
    private static Method setObserveModeMethod = null;
    
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
                                
                                // Find setObserveMode method
                                findObserveModeMethod();
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
     * Find the setObserveMode method in NativeNfcManager
     */
    private static void findObserveModeMethod() {
        if (nativeNfcManager == null) {
            XposedBridge.log(TAG + ": Cannot find method - nativeNfcManager is null");
            return;
        }
        
        Class<?> nmClass = nativeNfcManager.getClass();
        XposedBridge.log(TAG + ": Searching for setObserveMode in: " + nmClass.getName());
        
        // Try common method names for Observe Mode control
        String[] methodNames = {
            "setObserveMode",           // Standard naming
            "enableObserveMode",        // Alternative naming
            "nfcManager_setObserveMode", // JNI naming convention
            "doSetObserveMode"          // Alternative JNI naming
        };
        
        for (String methodName : methodNames) {
            try {
                setObserveModeMethod = nmClass.getMethod(methodName, boolean.class);
                setObserveModeMethod.setAccessible(true);
                XposedBridge.log(TAG + ": ✓ Found method: " + methodName);
                broadcaster.info("Observe Mode method found: " + methodName);
                return;
            } catch (NoSuchMethodException e) {
                // Try next method name
            }
        }
        
        // If not found, log available methods for debugging
        XposedBridge.log(TAG + ": ✗ setObserveMode method not found");
        XposedBridge.log(TAG + ": Available methods in " + nmClass.getName() + ":");
        
        Method[] methods = nmClass.getDeclaredMethods();
        for (Method m : methods) {
            String methodSignature = m.getName() + "(";
            Class<?>[] params = m.getParameterTypes();
            for (int i = 0; i < params.length; i++) {
                methodSignature += params[i].getSimpleName();
                if (i < params.length - 1) methodSignature += ", ";
            }
            methodSignature += ")";
            
            // Log methods that might be related to observe mode
            if (m.getName().toLowerCase().contains("observe") ||
                m.getName().toLowerCase().contains("mode") ||
                m.getName().toLowerCase().contains("polling")) {
                XposedBridge.log(TAG + ":   → " + methodSignature);
            }
        }
        
        broadcaster.warn("Observe Mode method not found - feature may not be available");
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
        
        if (setObserveModeMethod == null) {
            XposedBridge.log(TAG + ": ✗ Cannot enable - setObserveMode method not found");
            broadcaster.error("Observe Mode enable failed: method not available");
            return false;
        }
        
        try {
            // Call setObserveMode(true)
            Object result = setObserveModeMethod.invoke(nativeNfcManager, true);
            
            // Check result - be conservative with unknown return types
            boolean success = false;
            if (result instanceof Boolean) {
                success = (Boolean) result;
            } else if (result == null) {
                // Some methods return void, assume success if no exception
                success = true;
            } else {
                XposedBridge.log(TAG + ": ✗ Unexpected return type: " + result.getClass().getName());
                broadcaster.warn("Observe Mode returned unexpected type: " + result.getClass().getName());
                // Conservative: assume failure for unknown types
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
        
        if (setObserveModeMethod == null) {
            XposedBridge.log(TAG + ": ✗ Cannot disable - setObserveMode method not found");
            broadcaster.error("Observe Mode disable failed: method not available");
            return false;
        }
        
        try {
            // Call setObserveMode(false)
            Object result = setObserveModeMethod.invoke(nativeNfcManager, false);
            
            // Check result - be conservative with unknown return types
            boolean success = false;
            if (result instanceof Boolean) {
                success = (Boolean) result;
            } else if (result == null) {
                // Some methods return void, assume success if no exception
                success = true;
            } else {
                XposedBridge.log(TAG + ": ✗ Unexpected return type: " + result.getClass().getName());
                broadcaster.warn("Observe Mode returned unexpected type: " + result.getClass().getName());
                // Conservative: assume failure for unknown types
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
     * @return true if the required method was found
     */
    public static boolean isAvailable() {
        return nativeNfcManager != null && setObserveModeMethod != null;
    }
}
