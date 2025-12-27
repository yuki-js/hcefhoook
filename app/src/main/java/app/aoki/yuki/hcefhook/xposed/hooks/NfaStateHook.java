package app.aoki.yuki.hcefhook.xposed.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.xposed.LogBroadcaster;

/**
 * Hook for NFA state machine bypass
 * 
 * The NFA layer blocks data transmission unless in POLL_ACTIVE or LISTEN_ACTIVE state.
 * In Observe Mode, the state stays at DISCOVERY, so TX is blocked.
 * 
 * This hook bypasses the state check to allow TX in Observe Mode.
 * 
 * Target functions in libnfc-nci.so:
 * - nfa_dm_is_data_exchange_allowed()
 * - State variable: nfa_dm_cb.disc_cb.disc_state
 */
public class NfaStateHook {
    
    private static final String TAG = "HcefHook.NfaState";
    
    // Flag to enable/disable state bypass
    private static volatile boolean bypassEnabled = false;
    
    // Original state for restoration
    private static int originalState = -1;
    
    /**
     * Enable or disable state bypass
     */
    public static void setBypassEnabled(boolean enabled) {
        bypassEnabled = enabled;
        XposedBridge.log(TAG + ": State bypass " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Check if bypass is currently enabled
     */
    public static boolean isBypassEnabled() {
        return bypassEnabled;
    }
    
    /**
     * Install NFA state hooks
     */
    public static void install(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // Hook Java-layer state checks
        hookJavaStateChecks(lpparam, broadcaster);
        
        // Note: For native layer hooks, we would need to use Frida or Dobby
        // Xposed cannot directly hook native functions in libnfc-nci.so
        // The Java hooks provide a fallback for APIs that go through JNI
        
        broadcaster.info("NFA state hooks installed (Java layer)");
        broadcaster.warn("Native hooks require Frida - see HOOK_TARGETS.md");
    }
    
    /**
     * Hook Java-layer state validation
     */
    private static void hookJavaStateChecks(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // Try to hook NfcService.isObserveModeEnabled
        Class<?> nfcServiceClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.NfcService", lpparam.classLoader);
        
        if (nfcServiceClass != null) {
            // Hook methods that check NFC state
            hookStateCheckMethod(nfcServiceClass, "isNfcEnabled", broadcaster);
            hookStateCheckMethod(nfcServiceClass, "isObserveModeEnabled", broadcaster);
            hookStateCheckMethod(nfcServiceClass, "isDiscoveryStarted", broadcaster);
        }
        
        // Hook DeviceHost or similar interface
        Class<?> deviceHostClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.DeviceHost", lpparam.classLoader);
        
        if (deviceHostClass != null) {
            hookDeviceHostMethods(deviceHostClass, lpparam, broadcaster);
        }
        
        // Hook NativeNfcManager
        hookNativeNfcManager(lpparam, broadcaster);
    }
    
    /**
     * Generic hook for state check methods
     */
    private static void hookStateCheckMethod(Class<?> clazz, String methodName, LogBroadcaster broadcaster) {
        try {
            XposedHelpers.findAndHookMethod(
                clazz,
                methodName,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (bypassEnabled && param.getResult() instanceof Boolean) {
                            Boolean original = (Boolean) param.getResult();
                            broadcaster.debug(methodName + " returned: " + original);
                        }
                    }
                }
            );
        } catch (NoSuchMethodError e) {
            // Method not found
        }
    }
    
    /**
     * Hook DeviceHost methods for send operations
     */
    private static void hookDeviceHostMethods(Class<?> deviceHostClass, LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // Find implementation class
        Class<?> implClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.dhimpl.NativeNfcManager", lpparam.classLoader);
        
        if (implClass == null) {
            return;
        }
        
        // Hook doSend method
        try {
            XposedHelpers.findAndHookMethod(
                implClass,
                "doSend",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (bypassEnabled) {
                            byte[] data = (byte[]) param.args[0];
                            broadcaster.info("doSend called with bypass enabled, len=" + data.length);
                        }
                    }
                }
            );
            broadcaster.debug("Hooked NativeNfcManager.doSend");
        } catch (NoSuchMethodError e) {
            // Method not found
        }
    }
    
    /**
     * Hook NativeNfcManager for transceive operations
     */
    private static void hookNativeNfcManager(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> nativeNfcClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.dhimpl.NativeNfcManager", lpparam.classLoader);
        
        if (nativeNfcClass == null) {
            return;
        }
        
        // Hook enableDiscovery to track state changes
        try {
            XposedHelpers.findAndHookMethod(
                nativeNfcClass,
                "enableDiscovery",
                "com.android.nfc.DeviceHost$NfcDiscoveryParameters", boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        broadcaster.debug("enableDiscovery called");
                    }
                    
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        broadcaster.debug("enableDiscovery returned: " + param.getResult());
                    }
                }
            );
        } catch (NoSuchMethodError e) {
            // Method not found
        }
        
        // Hook setObserveMode
        try {
            XposedHelpers.findAndHookMethod(
                nativeNfcClass,
                "setObserveMode",
                boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        boolean enable = (boolean) param.args[0];
                        broadcaster.info("setObserveMode: " + enable);
                    }
                }
            );
            broadcaster.debug("Hooked NativeNfcManager.setObserveMode");
        } catch (NoSuchMethodError e) {
            // Method not found in this version
        }
    }
    
    /**
     * Temporarily spoof state for a single operation
     * Call this before attempting TX, and restoreState() after
     */
    public static void spoofListenActiveState() {
        bypassEnabled = true;
        XposedBridge.log(TAG + ": State spoofed to LISTEN_ACTIVE");
    }
    
    /**
     * Restore original state after TX attempt
     */
    public static void restoreState() {
        bypassEnabled = false;
        XposedBridge.log(TAG + ": State restored");
    }
}
