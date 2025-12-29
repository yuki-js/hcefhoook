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
 * When Observe Mode is enabled in the NFCC (via Xposed hooks in com.android.nfc process),
 * the NFCC sends polling frame data to the host via NCI_ANDROID_POLLING_FRAME_NTF notifications.
 * This hook intercepts those notifications to detect SENSF_REQ.
 * 
 * CRITICAL INTEGRATION: This hook detects SENSF_REQ and sends it to the app via IPC (Broadcast).
 * The app (MainActivity) then decides whether to auto-inject SENSF_RES.
 * 
 * Target: NfcService or NfcDispatcher classes that handle polling frames
 * 
 * NOTE: This code runs in the com.android.nfc process context, NOT the app's context.
 * Communication with the main app must use IPC (Broadcast, ContentProvider).
 */
public class PollingFrameHook {
    
    private static final String TAG = "HcefHook.PollingFrame";
    
    // Installation flag
    private static volatile boolean installed = false;
    
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
     * Check if hook is installed
     */
    public static boolean isInstalled() {
        return installed;
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
        // Hook NfcService.onPollingLoopDetected (the correct AOSP callback)
        // This is called when the NFCC sends polling frames in Observe Mode
        try {
            hookPollingLoopHandler(lpparam, broadcaster);
            installed = true;
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook polling loop: " + t.getMessage());
            broadcaster.error("Polling loop hook failed: " + t.getMessage());
        }
    }
    
    /**
     * Hook NfcService.onPollingLoopDetected
     * 
     * This is called when a polling frame is received in Observe Mode.
     * According to AOSP packages/apps/Nfc/src/com/android/nfc/NfcService.java:
     * 
     *   @Override
     *   public void onPollingLoopDetected(List<PollingFrame> frames) {
     *       if (mCardEmulationManager != null && android.nfc.Flags.nfcReadPollingLoop()) {
     *           mCardEmulationManager.onPollingLoopDetected(frames);
     *       }
     *   }
     * 
     * This method is part of the DeviceHost.DeviceHostListener interface.
     * The signature is: void onPollingLoopDetected(List<PollingFrame> frames)
     */
    private static void hookPollingLoopHandler(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> nfcServiceClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.NfcService", lpparam.classLoader);
        
        if (nfcServiceClass == null) {
            broadcaster.warn("NfcService class not found");
            return;
        }
        
        try {
            // Hook the correct AOSP method: onPollingLoopDetected(List<PollingFrame>)
            // Reference: DeviceHost.DeviceHostListener interface
            XposedHelpers.findAndHookMethod(
                nfcServiceClass,
                "onPollingLoopDetected",
                java.util.List.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        @SuppressWarnings("unchecked")
                        java.util.List<Object> frames = (java.util.List<Object>) param.args[0];
                        
                        XposedBridge.log(TAG + ": onPollingLoopDetected called with " + frames.size() + " frames");
                        broadcaster.info("Polling loop detected: " + frames.size() + " frames");
                        
                        // Process each PollingFrame
                        for (Object frameObj : frames) {
                            try {
                                // PollingFrame has public methods: getType() and getData()
                                // According to android.nfc.cardemulation.PollingFrame API
                                Class<?> pollingFrameClass = frameObj.getClass();
                                
                                // Use public API methods instead of private fields
                                Object typeObj = XposedHelpers.callMethod(frameObj, "getType");
                                Object dataObj = XposedHelpers.callMethod(frameObj, "getData");
                                
                                int type = (typeObj instanceof Integer) ? (Integer) typeObj : 0;
                                byte[] data = (dataObj instanceof byte[]) ? (byte[]) dataObj : new byte[0];
                                
                                // Log raw frame data prominently
                                String hexData = SensfResBuilder.toHexString(data);
                                broadcaster.info("=== RAW POLLING FRAME ===");
                                broadcaster.info("Type: " + type);
                                broadcaster.info("Data: " + hexData);
                                broadcaster.info("Length: " + data.length + " bytes");
                                broadcaster.debug("PollingFrame object: " + frameObj.getClass().getName());
                                
                                // Also log to Xposed bridge for debugging
                                XposedBridge.log(TAG + ": RAW FRAME - Type=" + type + " Data=" + hexData);
                                
                                // Process the frame data to detect SENSF_REQ
                                processPollingFrame(data, broadcaster);
                            } catch (Exception e) {
                                broadcaster.error("Failed to parse PollingFrame: " + e.getMessage());
                            }
                        }
                    }
                }
            );
            broadcaster.info("✓ Hooked: NfcService.onPollingLoopDetected(List<PollingFrame>)");
            
        } catch (Throwable t) {
            broadcaster.error("Failed to hook onPollingLoopDetected: " + t.getMessage());
            XposedBridge.log(TAG + ": Failed to hook onPollingLoopDetected: " + t.getMessage());
        }
    }
    
    /**
     * Process a polling frame and check for SENSF_REQ (SC=FFFF)
     */
    private static void processPollingFrame(byte[] frameData, LogBroadcaster broadcaster) {
        if (frameData == null || frameData.length < 6) {
            return;
        }
        
        broadcaster.debug("Processing polling frame: " + SensfResBuilder.toHexString(frameData));
        
        // Parse and detect SENSF_REQ
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
                    
                    // Attempt injection via SendRawFrameHook
                    SendRawFrameHook.injectSensfRes(sensfRes);
                } else {
                    broadcaster.info("Auto-inject disabled, queuing for manual injection");
                    // Queue for manual injection from app
                    ipcClient.queueInjection(sensfRes);
                }
            } catch (Exception e) {
                broadcaster.error("IPC failed: " + e.getMessage());
                // Fallback to direct injection attempt
                SendRawFrameHook.injectSensfRes(sensfRes);
            }
        } else {
            // No context, try direct injection
            SendRawFrameHook.injectSensfRes(sensfRes);
        }
    }
}
