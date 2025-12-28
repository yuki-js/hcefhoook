package app.aoki.yuki.hcefhook.xposed.hooks;

import android.content.Context;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.core.SensfResBuilder;
import app.aoki.yuki.hcefhook.xposed.LogBroadcaster;

/**
 * Hook for raw frame transmission
 * 
 * This hook intercepts and potentially bypasses the NFA_SendRawFrame function
 * to inject SENSF_RES frames in Observe Mode.
 * 
 * Key targets:
 * - NativeNfcManager.doTransceive() - Java JNI wrapper
 * - Native: NFA_SendRawFrame() in libnfc-nci.so (requires Frida)
 * 
 * NOTE: This code runs in the com.android.nfc process context.
 */
public class SendRawFrameHook {
    
    private static final String TAG = "HcefHook.SendRaw";
    
    // Context from hooked process
    private static Context hookedContext;
    
    // Pending SENSF_RES to inject
    private static byte[] pendingInjection = null;
    private static final AtomicBoolean injectionPending = new AtomicBoolean(false);
    private static final ExecutorService sprayExecutor =
        Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "hcef-spray");
            t.setDaemon(true);
            return t;
        });
    static {
        Runtime.getRuntime().addShutdownHook(new Thread(sprayExecutor::shutdown));
    }
    
    // Reference to native NFC manager for calling send methods
    private static Object nativeNfcManagerInstance = null;
    private static Method sendRawFrameMethod = null;
    private static Method transceiveMethod = null;
    
    /**
     * Set context obtained from hooked process
     */
    public static void setHookedContext(Context context) {
        hookedContext = context;
    }
    
    /**
     * Queue a SENSF_RES for injection
     */
    public static void injectSensfRes(byte[] sensfRes) {
        pendingInjection = sensfRes;
        injectionPending.set(true);
        XposedBridge.log(TAG + ": SENSF_RES queued for injection: " + 
            SensfResBuilder.toHexString(sensfRes));
        
        // Attempt immediate injection if manager is available
        attemptInjection();
    }

    /**
     * Spray multiple SENSF_RES frames to improve reliability
     */
    public static void spraySensfRes(byte[] sensfRes, int count, long intervalMs) {
        if (sensfRes == null || count <= 0) {
            return;
        }
        final byte[] frame = sensfRes;
        sprayExecutor.execute(() -> {
            for (int i = 0; i < count; i++) {
                injectSensfRes(frame);
                if (intervalMs > 0 && i + 1 < count) {
                    try {
                        Thread.sleep(intervalMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        });
    }

    public static void spraySensfRes(byte[] sensfRes) {
        spraySensfRes(sensfRes, Constants.SENSF_SPRAY_COUNT, Constants.SENSF_SPRAY_INTERVAL_MS);
    }
    
    /**
     * Install send raw frame hooks
     */
    public static void install(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        // Hook NativeNfcManager
        hookNativeNfcManager(lpparam, broadcaster);
        
        // Hook TagEndpoint for transceive
        hookTagEndpoint(lpparam, broadcaster);
        
        // Hook NfcService send methods
        hookNfcServiceSend(lpparam, broadcaster);
        
        broadcaster.info("Send raw frame hooks installed");
    }
    
    /**
     * Hook NativeNfcManager for raw frame operations
     */
    private static void hookNativeNfcManager(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> nativeNfcClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.dhimpl.NativeNfcManager", lpparam.classLoader);
        
        if (nativeNfcClass == null) {
            broadcaster.warn("NativeNfcManager class not found");
            return;
        }
        
        // Hook doTransceive to capture the method reference
        try {
            XposedHelpers.findAndHookMethod(
                nativeNfcClass,
                "doTransceive",
                byte[].class, boolean.class, int[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Store instance reference for later use
                        if (nativeNfcManagerInstance == null) {
                            nativeNfcManagerInstance = param.thisObject;
                            cacheTransceiveMethod(nativeNfcClass);
                        }
                        
                        byte[] data = (byte[]) param.args[0];
                        broadcaster.debug("doTransceive called, len=" + data.length);
                    }
                }
            );
            broadcaster.debug("Hooked NativeNfcManager.doTransceive");
        } catch (NoSuchMethodError e) {
            broadcaster.warn("doTransceive method not found");
        }
        
        // Hook doSend if available
        try {
            XposedHelpers.findAndHookMethod(
                nativeNfcClass,
                "doSend",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (nativeNfcManagerInstance == null) {
                            nativeNfcManagerInstance = param.thisObject;
                        }
                        
                        byte[] data = (byte[]) param.args[0];
                        broadcaster.debug("doSend called, len=" + data.length);
                    }
                }
            );
            broadcaster.debug("Hooked NativeNfcManager.doSend");
        } catch (NoSuchMethodError e) {
            // Method not found
        }
        
        // Hook getInstance or constructor to capture instance early
        try {
            XposedHelpers.findAndHookMethod(
                nativeNfcClass,
                "getInstance",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() != null) {
                            nativeNfcManagerInstance = param.getResult();
                            cacheTransceiveMethod(nativeNfcClass);
                            broadcaster.debug("Captured NativeNfcManager instance");
                        }
                    }
                }
            );
        } catch (NoSuchMethodError e) {
            // getInstance not available
        }
    }
    
    /**
     * Cache the transceive method for later invocation
     */
    private static void cacheTransceiveMethod(Class<?> nativeNfcClass) {
        if (transceiveMethod != null) return;
        
        try {
            transceiveMethod = nativeNfcClass.getDeclaredMethod(
                "doTransceive", byte[].class, boolean.class, int[].class);
            transceiveMethod.setAccessible(true);
            XposedBridge.log(TAG + ": Cached doTransceive method");
        } catch (NoSuchMethodException e) {
            XposedBridge.log(TAG + ": Could not cache doTransceive: " + e.getMessage());
        }
    }
    
    /**
     * Hook TagEndpoint for NFC-F operations
     */
    private static void hookTagEndpoint(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> tagEndpointClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.dhimpl.NativeNfcTag", lpparam.classLoader);
        
        if (tagEndpointClass == null) {
            return;
        }
        
        // Hook transceive method
        try {
            XposedHelpers.findAndHookMethod(
                tagEndpointClass,
                "transceive",
                byte[].class, boolean.class, int[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] data = (byte[]) param.args[0];
                        broadcaster.debug("NativeNfcTag.transceive called, len=" + data.length);
                    }
                }
            );
        } catch (NoSuchMethodError e) {
            // Method not found
        }
    }
    
    /**
     * Hook NfcService send methods
     */
    private static void hookNfcServiceSend(LoadPackageParam lpparam, LogBroadcaster broadcaster) {
        Class<?> nfcServiceClass = XposedHelpers.findClassIfExists(
            "com.android.nfc.NfcService", lpparam.classLoader);
        
        if (nfcServiceClass == null) {
            return;
        }
        
        // Hook sendData or similar methods
        String[] sendMethods = {"sendData", "send", "transceive"};
        
        for (String methodName : sendMethods) {
            try {
                // Try with byte[] parameter
                XposedHelpers.findAndHookMethod(
                    nfcServiceClass,
                    methodName,
                    byte[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            byte[] data = (byte[]) param.args[0];
                            broadcaster.debug("NfcService." + methodName + " called, len=" + data.length);
                        }
                    }
                );
                broadcaster.debug("Hooked NfcService." + methodName);
            } catch (NoSuchMethodError e) {
                // Method not found
            }
        }
    }
    
    /**
     * Attempt to inject the pending SENSF_RES
     */
    private static void attemptInjection() {
        if (!injectionPending.get() || pendingInjection == null) {
            return;
        }
        
        // Enable state bypass
        NfaStateHook.spoofListenActiveState();
        
        try {
            if (nativeNfcManagerInstance != null && transceiveMethod != null) {
                XposedBridge.log(TAG + ": Attempting SENSF_RES injection via transceive");
                
                int[] responseLen = new int[1];
                byte[] response = (byte[]) transceiveMethod.invoke(
                    nativeNfcManagerInstance, pendingInjection, false, responseLen);
                
                XposedBridge.log(TAG + ": Injection result: " + 
                    (response != null ? SensfResBuilder.toHexString(response) : "null"));
            } else {
                XposedBridge.log(TAG + ": Cannot inject - no NativeNfcManager instance");
            }
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Injection failed: " + e.getMessage());
        } finally {
            // Restore state
            NfaStateHook.restoreState();
            injectionPending.set(false);
            pendingInjection = null;
        }
    }
    
    /**
     * Force injection with custom SENSF_RES parameters
     */
    public static void forceInject(byte[] idm, byte[] pmm) {
        byte[] sensfRes = new SensfResBuilder()
            .setIdm(idm)
            .setPmm(pmm)
            .build();
        
        injectSensfRes(sensfRes);
    }
}
