package app.aoki.yuki.hcefhook.xposed.hooks;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.cardemulation.CardEmulation;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.xposed.LogBroadcaster;

/**
 * Hook for NFC Observe Mode - Complete Rewrite
 * 
 * WHAT WE'RE TRYING TO DO:
 * ========================
 * We want to enable Android's Observe Mode to passively receive polling frames
 * (especially SENSF_REQ with SC=FFFF) without the eSE auto-responding.
 * 
 * THE RIGHT WAY:
 * ==============
 * Use the official NfcAdapter API introduced in Android 15:
 * - NfcAdapter.isObserveModeSupported() - Check if device supports it
 * - NfcAdapter.isObserveModeEnabled() - Check current state
 * - NfcAdapter.setObserveMode(boolean enable, String packageName) - Enable/disable
 * 
 * We should NOT be hooking internal NfcService methods directly.
 * Instead, we provide a clean interface for the MainActivity to use the official API.
 * 
 * REFERENCE:
 * ==========
 * AOSP packages/apps/Nfc/src/com/android/nfc/NfcService.java
 * - Line 2221: public synchronized boolean setObserveMode(boolean enable, String packageName)
 * - Line 2195: public boolean isObserveModeSupported()
 * - Line 2209: public synchronized boolean isObserveModeEnabled()
 * 
 * NOTE: This code runs in the com.android.nfc process context.
 */
public class ObserveModeHook {
    
    private static final String TAG = "HcefHook.ObserveMode";
    
    // Reference to NfcAdapter for API access
    private static NfcAdapter nfcAdapter = null;
    
    // Context for logging
    private static LogBroadcaster broadcaster = null;
    
    // Context from android.nfc process
    private static Context nfcContext = null;
    
    /**
     * Install Observe Mode hooks
     * 
     * This is minimal - we just capture the NFC context and adapter.
     * The actual ObserveMode control happens via official NfcAdapter API.
     */
    public static void install(LoadPackageParam lpparam, LogBroadcaster logBroadcaster) {
        broadcaster = logBroadcaster;
        
        try {
            // Hook Application.attach to get NFC service context
            XposedHelpers.findAndHookMethod(
                "android.app.Application",
                lpparam.classLoader,
                "attach",
                Context.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        nfcContext = (Context) param.args[0];
                        XposedBridge.log(TAG + ": Captured NFC context");
                        
                        // Get NfcAdapter using official API
                        try {
                            nfcAdapter = NfcAdapter.getDefaultAdapter(nfcContext);
                            if (nfcAdapter != null) {
                                XposedBridge.log(TAG + ": ✓ Got NfcAdapter instance");
                                broadcaster.info("NfcAdapter ready for Observe Mode control");
                                
                                // Check Observe Mode support
                                try {
                                    boolean supported = (boolean) XposedHelpers.callMethod(
                                        nfcAdapter, "isObserveModeSupported");
                                    XposedBridge.log(TAG + ": Observe Mode supported: " + supported);
                                    broadcaster.info("Observe Mode supported: " + supported);
                                } catch (Exception e) {
                                    XposedBridge.log(TAG + ": isObserveModeSupported() not available: " + e.getMessage());
                                    broadcaster.warn("Observe Mode API may not be available on this device");
                                }
                            } else {
                                XposedBridge.log(TAG + ": ✗ NfcAdapter is null");
                                broadcaster.warn("Failed to get NfcAdapter");
                            }
                        } catch (Exception e) {
                            XposedBridge.log(TAG + ": Failed to get NfcAdapter: " + e.getMessage());
                            broadcaster.error("NfcAdapter initialization failed: " + e.getMessage());
                        }
                    }
                }
            );
            
            broadcaster.info("ObserveModeHook installed (minimal - using official API)");
            
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to install hook: " + t.getMessage());
            broadcaster.error("ObserveModeHook installation failed: " + t.getMessage());
        }
    }
    
    /**
     * Enable Observe Mode using official NfcAdapter API
     * 
     * Uses: NfcAdapter.setObserveModeEnabled(true)
     * 
     * @return true if successful, false otherwise
     */
    public static boolean enableObserveMode() {
        XposedBridge.log(TAG + ": enableObserveMode() called");
        
        if (nfcAdapter == null) {
            XposedBridge.log(TAG + ": ✗ Cannot enable - NfcAdapter not available");
            broadcaster.error("Observe Mode enable failed: NfcAdapter not ready");
            return false;
        }
        
        try {
            // Call official NfcAdapter.setObserveModeEnabled(true) API
            // This is the correct public API method!
            XposedHelpers.callMethod(nfcAdapter, "setObserveModeEnabled", true);
            
            XposedBridge.log(TAG + ": ✓✓✓ Observe Mode ENABLED via setObserveModeEnabled() ✓✓✓");
            broadcaster.info("*** Observe Mode ENABLED (NfcAdapter.setObserveModeEnabled) ***");
            broadcaster.info("NFCC is now in passive observation mode");
            broadcaster.info("eSE will not respond to SENSF_REQ");
            
            // Verify the state
            try {
                boolean enabled = (boolean) XposedHelpers.callMethod(
                    nfcAdapter, "isObserveModeEnabled");
                XposedBridge.log(TAG + ": Verified state - isObserveModeEnabled: " + enabled);
                broadcaster.info("Verified: isObserveModeEnabled() = " + enabled);
                return enabled;
            } catch (Exception e) {
                XposedBridge.log(TAG + ": Could not verify state: " + e.getMessage());
                // Assume success if setObserveModeEnabled didn't throw
                return true;
            }
            
        } catch (Exception e) {
            XposedBridge.log(TAG + ": ✗ Exception enabling Observe Mode: " + e.getMessage());
            e.printStackTrace();
            broadcaster.error("Observe Mode enable exception: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Disable Observe Mode using official NfcAdapter API
     * 
     * Uses: NfcAdapter.setObserveModeEnabled(false)
     * 
     * @return true if successful, false otherwise
     */
    public static boolean disableObserveMode() {
        XposedBridge.log(TAG + ": disableObserveMode() called");
        
        if (nfcAdapter == null) {
            XposedBridge.log(TAG + ": ✗ Cannot disable - NfcAdapter not available");
            broadcaster.error("Observe Mode disable failed: NfcAdapter not ready");
            return false;
        }
        
        try {
            // Call official NfcAdapter.setObserveModeEnabled(false) API
            XposedHelpers.callMethod(nfcAdapter, "setObserveModeEnabled", false);
            
            XposedBridge.log(TAG + ": ✓ Observe Mode DISABLED via setObserveModeEnabled()");
            broadcaster.info("Observe Mode DISABLED (NfcAdapter.setObserveModeEnabled)");
            broadcaster.info("NFCC returned to normal mode");
            
            // Verify the state
            try {
                boolean enabled = (boolean) XposedHelpers.callMethod(
                    nfcAdapter, "isObserveModeEnabled");
                XposedBridge.log(TAG + ": Verified state - isObserveModeEnabled: " + enabled);
                broadcaster.info("Verified: isObserveModeEnabled() = " + enabled);
                return !enabled;
            } catch (Exception e) {
                XposedBridge.log(TAG + ": Could not verify state: " + e.getMessage());
                return true;
            }
            
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
     * @return true if NfcAdapter is available
     */
    public static boolean isAvailable() {
        return nfcAdapter != null && nfcContext != null;
    }
    
    /**
     * Check if Observe Mode is currently enabled
     * 
     * @return true if enabled, false otherwise
     */
    public static boolean isEnabled() {
        if (nfcAdapter == null) {
            return false;
        }
        
        try {
            return (boolean) XposedHelpers.callMethod(nfcAdapter, "isObserveModeEnabled");
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Failed to check Observe Mode state: " + e.getMessage());
            return false;
        }
    }
}
