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
                        if (lpparam.packageName.equals("com.android.nfc")) {
                            try {
                                XposedBridge.log(TAG + ": Installing Dobby native hooks in android.nfc process");
                                boolean success = app.aoki.yuki.hcefhook.nativehook.DobbyHooks.install();
                                if (success) {
                                    XposedBridge.log(TAG + ": Dobby hooks installed successfully");
                                    app.aoki.yuki.hcefhook.nativehook.DobbyHooks.logStatus();
                                } else {
                                    XposedBridge.log(TAG + ": WARNING: Dobby hooks installation failed");
                                }
                            } catch (Throwable dobbyError) {
                                XposedBridge.log(TAG + ": Dobby hook error: " + dobbyError.getMessage());
                                dobbyError.printStackTrace();
                            }
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
     * Start a background thread to poll for Observe Mode commands
     * Thread-safe: only starts once
     * 
     * CRITICAL: Uses IPC (ContentResolver) to communicate across process boundaries
     * XposedInit runs in com.android.nfc process, HookIpcProvider in app process
     */
    private void startCommandPolling() {
        synchronized (pollingLock) {
            if (commandPollingStarted) {
                XposedBridge.log(TAG + ": Command polling already started, skipping");
                return;
            }
            commandPollingStarted = true;
        }
        
        new Thread(() -> {
            XposedBridge.log(TAG + ": Command polling thread started");
            
            // Wait for appContext to be available
            while (appContext == null) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    return;
                }
            }
            
            XposedBridge.log(TAG + ": Context available, starting command polling");
            
            while (true) {
                try {
                    // CRITICAL FIX: Use IPC via ContentResolver, not direct static method call
                    // This works across process boundaries (com.android.nfc <-> app.aoki.yuki.hcefhook)
                    android.content.ContentResolver resolver = appContext.getContentResolver();
                    android.net.Uri commandUri = android.net.Uri.parse(
                        "content://app.aoki.yuki.hcefhook.ipc/config/pending_observe_mode_command");
                    
                    android.database.Cursor cursor = resolver.query(commandUri, null, null, null, null);
                    String command = null;
                    
                    if (cursor != null && cursor.moveToFirst()) {
                        int valueIndex = cursor.getColumnIndex("value");
                        if (valueIndex >= 0) {
                            command = cursor.getString(valueIndex);
                        }
                        cursor.close();
                    }
                    
                    if (command != null && !command.isEmpty()) {
                        XposedBridge.log(TAG + ": Processing command via IPC: " + command);
                        
                        // Clear the command immediately to avoid re-processing
                        android.content.ContentValues clearCmd = new android.content.ContentValues();
                        clearCmd.put("key", "pending_observe_mode_command");
                        clearCmd.put("value", "");
                        resolver.insert(commandUri, clearCmd);
                        
                        if ("ENABLE".equals(command)) {
                            boolean success = ObserveModeHook.enableObserveMode();
                            if (success) {
                                broadcaster.info("✓ Observe Mode enabled successfully");
                            } else {
                                broadcaster.error("✗ Failed to enable Observe Mode");
                            }
                        } else if ("DISABLE".equals(command)) {
                            boolean success = ObserveModeHook.disableObserveMode();
                            if (success) {
                                broadcaster.info("✓ Observe Mode disabled successfully");
                            } else {
                                broadcaster.error("✗ Failed to disable Observe Mode");
                            }
                        }
                    }
                    
                    // Poll every 1000ms (1 second) to reduce CPU usage
                    Thread.sleep(1000);
                    
                } catch (InterruptedException e) {
                    XposedBridge.log(TAG + ": Command polling interrupted");
                    break;
                } catch (Exception e) {
                    XposedBridge.log(TAG + ": Command polling error: " + e.getMessage());
                    // Continue polling even on errors
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        break;
                    }
                }
            }
        }).start();
    }
}
