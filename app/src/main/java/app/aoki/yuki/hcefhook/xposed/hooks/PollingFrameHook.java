package app.aoki.yuki.hcefhook.xposed.hooks;

import android.content.Context;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.core.SensfResBuilder;
import app.aoki.yuki.hcefhook.xposed.LogBroadcaster;

/**
 * Hook for polling frame notifications in Observe Mode
 * 
 * When Observe Mode is enabled, the NFCC sends polling frame data
 * to the host via NCI_ANDROID_POLLING_FRAME_NTF notifications.
 * This hook intercepts those notifications to detect SENSF_REQ.
 * 
 * Target: NfcService or NfcDispatcher classes that handle polling frames
 * 
 * NOTE: This code runs in the com.android.nfc process context, NOT the app's context.
 * Communication with the main app must use IPC (Broadcast, ContentProvider).
 */
public class PollingFrameHook {
    
    private static final String TAG = "HcefHook.PollingFrame";
    
    // Callback for SENSF_REQ detection
    private static SensfReqCallback callback;
    
    // Context from hooked process (com.android.nfc)
    private static Context hookedContext;
    
    public interface SensfReqCallback {
        void onSensfReqDetected(byte[] reqData, int systemCode);
    }
    
    public static void setCallback(SensfReqCallback cb) {
        callback = cb;
    }
    
    /**
     * Set context obtained from hooked process
     */
    public static void setHookedContext(Context context) {
        hookedContext = context;
    }
    
    /**
     * Install polling frame hooks
     */
    public static void install(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // Try to hook NfcService.onPollingLoopDetected or similar
        // The exact method name may vary by Android version
        
        try {
            // Hook NfcService polling loop handler (Android 15+)
            hookPollingLoopHandler(lpparam, broadcaster);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook polling loop: " + t.getMessage());
            broadcaster.warn("Polling loop hook failed: " + t.getMessage());
        }
        
        try {
            // Hook NfcDispatcher for lower-level access
            hookNfcDispatcher(lpparam, broadcaster);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook NfcDispatcher: " + t.getMessage());
        }
        
        // Try to hook native layer notification handling
        try {
            hookNativeNotification(lpparam, broadcaster);
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Native notification hook unavailable: " + t.getMessage());
        }
    }
    
    /**
     * Hook NfcService.onPollingLoopDetected
     * This is called when a polling frame is received in Observe Mode
     */
    private static void hookPollingLoopHandler(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> nfcServiceClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.NfcService", lpparam.classLoader);
        
        if (nfcServiceClass == null) {
            broadcaster.warn("NfcService class not found");
            return;
        }
        
        // Try different method names for polling loop detection
        String[] methodNames = {
            "onPollingLoopDetected",
            "handlePollingFrame",
            "processPollingFrame",
            "onObserveModePollingFrame"
        };
        
        for (String methodName : methodNames) {
            try {
                XposedHelpers.findAndHookMethod(
                    nfcServiceClass,
                    methodName,
                    byte[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            byte[] frameData = (byte[]) param.args[0];
                            processPollingFrame(frameData, broadcaster);
                        }
                    }
                );
                broadcaster.info("Hooked: NfcService." + methodName);
                return;
            } catch (NoSuchMethodError e) {
                // Try next method name
            }
        }
        
        broadcaster.warn("No polling loop method found in NfcService");
    }
    
    /**
     * Hook NfcDispatcher for polling frame handling
     */
    private static void hookNfcDispatcher(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> dispatcherClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.NfcDispatcher", lpparam.classLoader);
        
        if (dispatcherClass == null) {
            return;
        }
        
        // Hook dispatch method that handles NFC events
        try {
            XposedHelpers.findAndHookMethod(
                dispatcherClass,
                "dispatchTag",
                "android.nfc.Tag",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log(TAG + ": dispatchTag called");
                        broadcaster.debug("NfcDispatcher.dispatchTag called");
                    }
                }
            );
        } catch (NoSuchMethodError e) {
            // Method may not exist in this version
        }
    }
    
    /**
     * Attempt to hook native JNI notification handler
     */
    private static void hookNativeNotification(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // NfcJniNative or similar class handles JNI calls
        Class<?> jniClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.dhimpl.NativeNfcManager", lpparam.classLoader);
        
        if (jniClass == null) {
            jniClass = XposedHelpers.findClassIfExists(
                "com.android.nfc.NfcJniNative", lpparam.classLoader);
        }
        
        if (jniClass == null) {
            return;
        }
        
        // Try to hook notification callbacks
        try {
            XposedHelpers.findAndHookMethod(
                jniClass,
                "notifyPollingLoopFrame",
                int.class, byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        int type = (int) param.args[0];
                        byte[] data = (byte[]) param.args[1];
                        broadcaster.debug("Native polling frame: type=" + type);
                        processPollingFrame(data, broadcaster);
                    }
                }
            );
            broadcaster.info("Hooked native polling frame notification");
        } catch (NoSuchMethodError e) {
            // Method not found
        }
    }
    
    /**
     * Process a polling frame and check for SENSF_REQ (SC=FFFF)
     */
    private static void processPollingFrame(byte[] frameData, LogBroadcaster broadcaster) {
        if (frameData == null || frameData.length < 6) {
            return;
        }
        
        // SENSF_REQ format: [Length][0x00][SC_H][SC_L][RC][TSN]
        // Check if this is a SENSF_REQ (cmd = 0x00)
        int cmd = frameData[1] & 0xFF;
        if (cmd != Constants.SENSF_REQ_CMD) {
            return;
        }
        
        // Extract system code
        int scHigh = frameData[2] & 0xFF;
        int scLow = frameData[3] & 0xFF;
        int systemCode = (scHigh << 8) | scLow;
        
        String msg = String.format("SENSF_REQ detected: SC=0x%04X, data=%s",
            systemCode, SensfResBuilder.toHexString(frameData));
        XposedBridge.log(TAG + ": " + msg);
        broadcaster.info(msg);
        
        // Check for wildcard system code
        if (systemCode == Constants.SYSTEM_CODE_WILDCARD) {
            broadcaster.info("*** Wildcard SENSF_REQ (SC=FFFF) detected! ***");
            broadcaster.notifySensfDetected(frameData, systemCode);
            
            // Trigger callback for SENSF_RES injection
            if (callback != null) {
                callback.onSensfReqDetected(frameData, systemCode);
            }
            
            // Attempt to inject SENSF_RES (using hooked process context for IPC)
            triggerSensfResInjection(broadcaster, hookedContext);
        }
    }
    
    /**
     * Trigger SENSF_RES injection after detecting wildcard poll
     * 
     * NOTE: This runs in the hooked process (com.android.nfc) context.
     * We cannot directly call app methods. Use IPC via ContentProvider.
     */
    private static void triggerSensfResInjection(LogBroadcaster broadcaster, Context context) {
        byte[] sensfRes = SensfResBuilder.buildDefault();
        String resHex = SensfResBuilder.toHexString(sensfRes);
        broadcaster.info("Prepared SENSF_RES: " + resHex);
        
        // Check if auto-inject is enabled via IPC
        if (context != null) {
            try {
                app.aoki.yuki.hcefhook.ipc.IpcClient ipcClient = 
                    new app.aoki.yuki.hcefhook.ipc.IpcClient(context);
                
                if (ipcClient.isAutoInjectEnabled()) {
                    // Get custom IDm/PMm if configured
                    byte[] customIdm = ipcClient.getIdm();
                    byte[] customPmm = ipcClient.getPmm();
                    
                    if (customIdm != null && customPmm != null) {
                        sensfRes = new SensfResBuilder()
                            .setIdm(customIdm)
                            .setPmm(customPmm)
                            .build();
                        broadcaster.info("Using custom IDm/PMm from config");
                    }
                    
                    // Attempt spray injection via SendRawFrameHook
                    SendRawFrameHook.spraySensfRes(sensfRes);
                } else {
                    broadcaster.info("Auto-inject disabled, queuing for manual injection");
                    // Queue for manual injection from app
                    ipcClient.queueInjection(sensfRes);
                }
            } catch (Exception e) {
                broadcaster.error("IPC failed: " + e.getMessage());
                // Fallback to direct injection attempt
                SendRawFrameHook.spraySensfRes(sensfRes);
            }
        } else {
            // No context, try direct injection
            SendRawFrameHook.spraySensfRes(sensfRes);
        }
    }
}
