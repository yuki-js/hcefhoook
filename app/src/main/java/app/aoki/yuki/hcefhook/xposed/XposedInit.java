package app.aoki.yuki.hcefhook.xposed;

import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.nativehook.NativeHook;
import app.aoki.yuki.hcefhook.xposed.hooks.NfaStateHook;
import app.aoki.yuki.hcefhook.xposed.hooks.PollingFrameHook;
import app.aoki.yuki.hcefhook.xposed.hooks.SendRawFrameHook;

/**
 * Xposed Module entry point for HCE-F Observe Mode SENSF_RES Injection
 * 
 * This module hooks the Android NFC stack to:
 * 1. Detect SENSF_REQ (SC=FFFF) in Observe Mode
 * 2. Bypass NFA/NCI state machine checks that block TX
 * 3. Inject custom SENSF_RES with specified IDm/PMm
 */
public class XposedInit implements IXposedHookLoadPackage {
    
    private static final String TAG = "HcefHook.XposedInit";
    
    private Context appContext;
    private LogBroadcaster broadcaster;
    
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        // Only hook NFC-related packages
        if (!isTargetPackage(lpparam.packageName)) {
            return;
        }
        
        XposedBridge.log(TAG + ": Hooking package: " + lpparam.packageName);
        
        // Hook Application.attach to get context
        hookApplicationContext(lpparam);
        
        // Create broadcaster with lazy context provider
        ContextProvider provider = new ContextProvider() {
            @Override
            public Context getContext() {
                return appContext;
            }
        };
        broadcaster = new LogBroadcaster(provider, lpparam.packageName);
        
        // Install hooks based on target package
        if (lpparam.packageName.equals("com.android.nfc")) {
            installNfcServiceHooks(lpparam);
        }
    }
    
    /**
     * Check if this package should be hooked
     */
    private boolean isTargetPackage(String packageName) {
        return packageName.equals("com.android.nfc") ||
               packageName.equals("com.google.android.nfc");
    }
    
    /**
     * Hook Application.attach to obtain Context
     */
    private void hookApplicationContext(LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.Application",
                lpparam.classLoader,
                "attach",
                Context.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        appContext = (Context) param.args[0];
                        XposedBridge.log(TAG + ": Got application context");
                        
                        // Set context for hooks that need IPC
                        PollingFrameHook.setHookedContext(appContext);
                        SendRawFrameHook.setHookedContext(appContext);
                        
                        // Notify main app that hook is active via IPC
                        try {
                            app.aoki.yuki.hcefhook.ipc.IpcClient ipcClient = 
                                new app.aoki.yuki.hcefhook.ipc.IpcClient(appContext);
                            ipcClient.setHookActive(true);
                        } catch (Exception e) {
                            XposedBridge.log(TAG + ": Failed to notify app: " + e.getMessage());
                        }
                        
                        if (broadcaster != null) {
                            broadcaster.info("HCE-F hooks installed for: " + lpparam.packageName);
                        }
                    }
                }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook Application.attach: " + t.getMessage());
        }
    }
    
    /**
     * Install hooks for NFC service (com.android.nfc)
     */
    private void installNfcServiceHooks(LoadPackageParam lpparam) {
        // Hook 1: Polling frame notification handler
        // This detects SENSF_REQ when in Observe Mode
        PollingFrameHook.install(lpparam, broadcaster);
        
        // Hook 2: NFA state machine bypass
        // This allows data TX in Observe Mode (DISCOVERY state)
        NfaStateHook.install(lpparam, broadcaster);
        
        // Hook 3: Raw frame send function
        // This is where we inject our SENSF_RES
        SendRawFrameHook.install(lpparam, broadcaster);
        
        initializeNativeHooks();
        broadcaster.info("All NFC service hooks installed");
    }

    /**
     * Initialize native hooks inside the com.android.nfc process
     */
    private void initializeNativeHooks() {
        try {
            if (NativeHook.isInitialized()) {
                return;
            }
            boolean ok = NativeHook.initialize();
            if (broadcaster == null) {
                return;
            }
            if (ok) {
                broadcaster.info("Native hook initialized in com.android.nfc process");
            } else {
                broadcaster.warn("Native hook initialization failed in target process");
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Native hook init error: " + t.getMessage());
        }
    }
}
