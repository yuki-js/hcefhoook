package app.aoki.yuki.hcefhook.xposed;

import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.xposed.hooks.NfaStateHook;
import app.aoki.yuki.hcefhook.xposed.hooks.ObserveModeHook;
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
    
    // Thread safety for command polling
    private static volatile boolean commandPollingStarted = false;
    private static final Object pollingLock = new Object();
    
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
                        
                        // Initialize Dobby native hooks in android.nfc process
                        // CRITICAL: This ensures hooks run in the correct process context
                        // NOTE: Must wait for NFC JNI library to be loaded first
                        if (lpparam.packageName.equals("com.android.nfc")) {
                            installDobbyHooksAsync();
                        }
                        
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
        // Hook 0: Observe Mode control
        // This enables/disables NFC Observe Mode via IPC commands
        ObserveModeHook.install(lpparam, broadcaster);
        
        // Hook 1: Polling frame notification handler
        // This detects SENSF_REQ when in Observe Mode
        PollingFrameHook.install(lpparam, broadcaster);
        
        // Hook 2: NFA state machine bypass
        // This allows data TX in Observe Mode (DISCOVERY state)
        NfaStateHook.install(lpparam, broadcaster);
        
        // Hook 3: Raw frame send function
        // This is where we inject our SENSF_RES
        SendRawFrameHook.install(lpparam, broadcaster);
        
        // Start command polling thread to check for Observe Mode commands
        startCommandPolling();
        
        broadcaster.info("All NFC service hooks installed");
    }
    
    /**
     * Start command polling thread (DEPRECATED)
     * 
     * REMOVED: Hooks should be PASSIVE observers, not active controllers.
     * This command polling mechanism tried to enable Observe Mode from hooks,
     * which is architecturally incorrect. MainActivity now controls Observe Mode directly.
     */
    @Deprecated
    private void startCommandPolling() {
        synchronized (pollingLock) {
            if (commandPollingStarted) {
                XposedBridge.log(TAG + ": Command polling NOT started (feature removed - hooks are passive)");
                return;
            }
            commandPollingStarted = true;
        }
        
        XposedBridge.log(TAG + ": Command polling DISABLED - hooks are now passive observers");
        XposedBridge.log(TAG + ": Observe Mode is controlled by MainActivity, not by hooks");
        broadcaster.info("Command polling disabled - using passive hook architecture");
    }
    
    /**
     * Install Dobby hooks asynchronously with retry logic
     * 
     * CRITICAL FIX: The NFC JNI library (libstnfc_nci_jni.so or libnfc_nci_jni.so)
     * may not be loaded yet when Application.attach() runs. We need to wait for
     * the library to be loaded before attempting to install hooks.
     * 
     * Strategy:
     * - Poll /proc/self/maps for the library
     * - Retry with exponential backoff
     * - Give up after 30 seconds
     */
    private void installDobbyHooksAsync() {
        new Thread(() -> {
            XposedBridge.log(TAG + ": Starting async Dobby hook installation");
            
            final String[] libraryNames = {
                "libstnfc_nci_jni.so",    // ST NFC chipset (common on real devices)
                "libnfc_nci_jni.so",      // Standard AOSP name
                "libnfc-nci.so"           // Alternative name
            };
            
            final int MAX_ATTEMPTS = 30;  // 30 attempts
            final int INITIAL_DELAY_MS = 500;  // Start with 500ms
            final int MAX_DELAY_MS = 2000;     // Cap at 2 seconds
            
            boolean libraryFound = false;
            int attempts = 0;
            int currentDelay = INITIAL_DELAY_MS;
            
            // Wait for library to be loaded
            while (!libraryFound && attempts < MAX_ATTEMPTS) {
                attempts++;
                
                try {
                    // Check if any of the NFC libraries are loaded
                    // Use try-with-resources to ensure reader is closed
                    try (java.io.BufferedReader reader = new java.io.BufferedReader(
                            new java.io.FileReader("/proc/self/maps"))) {
                        String line;
                        
                        while ((line = reader.readLine()) != null) {
                            for (String libName : libraryNames) {
                                if (line.contains(libName)) {
                                    libraryFound = true;
                                    XposedBridge.log(TAG + ": Found NFC library: " + libName + " (attempt " + attempts + ")");
                                    break;
                                }
                            }
                            if (libraryFound) break;
                        }
                    } // reader auto-closed here
                    
                    if (!libraryFound) {
                        XposedBridge.log(TAG + ": NFC library not loaded yet, waiting " + currentDelay + "ms (attempt " + attempts + "/" + MAX_ATTEMPTS + ")");
                        Thread.sleep(currentDelay);
                        // Exponential backoff with cap
                        currentDelay = Math.min(currentDelay * 2, MAX_DELAY_MS);
                    }
                    
                } catch (Exception e) {
                    XposedBridge.log(TAG + ": Error checking for NFC library: " + e.getMessage());
                    try {
                        Thread.sleep(currentDelay);
                    } catch (InterruptedException ie) {
                        return;
                    }
                }
            }
            
            if (!libraryFound) {
                XposedBridge.log(TAG + ": FATAL: NFC library not found after " + MAX_ATTEMPTS + " attempts");
                XposedBridge.log(TAG + ": Native hooks will NOT be installed");
                XposedBridge.log(TAG + ": Expected libraries: " + java.util.Arrays.toString(libraryNames));
                return;
            }
            
            // Library is loaded, now initialize coordination
            // NOTE: Dobby has been replaced with Frida for native hooking
            // This now just logs status and coordinates with Frida script
            XposedBridge.log(TAG + ": NFC library is loaded, initializing hook coordination...");
            
            try {
                boolean success = app.aoki.yuki.hcefhook.nativehook.DobbyHooks.install();
                if (success) {
                    XposedBridge.log(TAG + ": ✓✓✓ Hook coordination initialized");
                    XposedBridge.log(TAG + ": NOTE: For native TX bypass, run Frida script:");
                    XposedBridge.log(TAG + ":   frida -U -f com.android.nfc -l observe_mode_bypass.js");
                    app.aoki.yuki.hcefhook.nativehook.DobbyHooks.logStatus();
                } else {
                    XposedBridge.log(TAG + ": WARNING: Hook coordination initialization failed");
                }
            } catch (Throwable hookError) {
                XposedBridge.log(TAG + ": Hook coordination error: " + hookError.getMessage());
                hookError.printStackTrace();
            }
            
        }, "NativeHookCoordinator").start();
    }
}
