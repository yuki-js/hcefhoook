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
 * Hook for NFC Observe Mode - PASSIVE MONITORING ONLY
 * 
 * CRITICAL ARCHITECTURAL PRINCIPLE:
 * ====================================
 * This hook runs in com.android.nfc process and should ONLY observe and log.
 * It must NOT actively enable or control Observe Mode!
 * 
 * WHY:
 * - Observe Mode is Activity-bound and must be controlled by the Activity itself
 * - MainActivity runs in app process and calls NfcAdapter.setObserveModeEnabled() directly
 * - Hooks running in com.android.nfc can OBSERVE but must not CONTROL
 * - Trying to get NfcAdapter in com.android.nfc process is wrong (NfcAdapter is for consumers, not producers)
 * 
 * WHAT THIS HOOK DOES:
 * ====================
 * 1. Monitors when Observe Mode is enabled/disabled (passively)
 * 2. Logs state changes for debugging
 * 3. Intercepts and logs polling frame notifications
 * 4. Does NOT call any enable/disable methods
 * 
 * REFERENCE:
 * ==========
 * AOSP packages/apps/Nfc/src/com/android/nfc/NfcService.java
 * - setObserveMode() is called by applications via NfcAdapter
 * - We hook this to observe when apps enable/disable Observe Mode
 * - We do NOT call it ourselves
 */
public class ObserveModeHook {
    
    private static final String TAG = "HcefHook.ObserveMode";
    
    // Context for logging (from com.android.nfc process)
    private static Context nfcContext = null;
    private static LogBroadcaster broadcaster = null;
    
    /**
     * Install PASSIVE Observe Mode monitoring hooks
     * 
     * This hook is minimal and non-invasive:
     * - Captures NFC service context for logging
     * - Hooks setObserveMode() to log when it's called by apps
     * - Hooks isObserveModeEnabled() to log state queries
     * - Does NOT enable Observe Mode itself
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
                        XposedBridge.log(TAG + ": Captured NFC service context (for logging only)");
                    }
                }
            );
            
            // Hook NfcService.setObserveMode() to OBSERVE when it's called
            try {
                XposedHelpers.findAndHookMethod(
                    "com.android.nfc.NfcService",
                    lpparam.classLoader,
                    "setObserveMode",
                    boolean.class,
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            boolean enable = (boolean) param.args[0];
                            String packageName = (String) param.args[1];
                            
                            XposedBridge.log(TAG + ": setObserveMode() called by " + packageName + 
                                           " with enable=" + enable);
                            broadcaster.info("Observe Mode " + (enable ? "ENABLED" : "DISABLED") + 
                                           " by " + packageName);
                        }
                        
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            boolean result = (boolean) param.getResult();
                            XposedBridge.log(TAG + ": setObserveMode() returned: " + result);
                            broadcaster.info("setObserveMode result: " + result);
                        }
                    }
                );
                broadcaster.info("Hooked NfcService.setObserveMode() for monitoring");
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": Could not hook setObserveMode: " + t.getMessage());
                broadcaster.warn("setObserveMode hook failed (may not be available on this device)");
            }
            
            // Hook isObserveModeEnabled() to monitor state queries
            try {
                XposedHelpers.findAndHookMethod(
                    "com.android.nfc.NfcService",
                    lpparam.classLoader,
                    "isObserveModeEnabled",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            boolean enabled = (boolean) param.getResult();
                            XposedBridge.log(TAG + ": isObserveModeEnabled() = " + enabled);
                        }
                    }
                );
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": Could not hook isObserveModeEnabled: " + t.getMessage());
            }
            
            broadcaster.info("ObserveModeHook installed (PASSIVE monitoring only)");
            broadcaster.info("This hook does NOT enable Observe Mode - MainActivity does that!");
            
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to install hook: " + t.getMessage());
            broadcaster.error("ObserveModeHook installation failed: " + t.getMessage());
        }
    }
    
    /**
     * REMOVED: enableObserveMode()
     * 
     * This method has been removed because it's architecturally incorrect.
     * Observe Mode MUST be enabled by MainActivity using NfcAdapter.setObserveModeEnabled().
     * Hooks should be PASSIVE observers, not active controllers.
     */
    
    /**
     * REMOVED: disableObserveMode()
     * 
     * Same reason as above - MainActivity controls Observe Mode, not hooks.
     */
    
    /**
     * Check if hook is available (context captured)
     * 
     * @return true if NFC service context is available
     */
    public static boolean isAvailable() {
        return nfcContext != null;
    }
}
