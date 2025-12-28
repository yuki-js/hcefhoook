package app.aoki.yuki.hcefhook.xposed.hooks;

import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.XposedBridge;

import app.aoki.yuki.hcefhook.core.SensfResBuilder;
import app.aoki.yuki.hcefhook.nativehook.DobbyHooks;

/**
 * Spray Mode Controller for Continuous SENSF_RES Transmission
 * 
 * Implements the "Spray Strategy" to compensate for Android's inability to meet
 * the 2.4ms FeliCa response time constraint. Instead of trying to respond precisely,
 * we continuously transmit SENSF_RES for a window of time, increasing the probability
 * that the reader will successfully receive at least one response.
 * 
 * Strategy:
 * 1. Detect SENSF_REQ in Observe Mode
 * 2. Immediately send first SENSF_RES
 * 3. Continue sending at ~1-2ms intervals for 20ms total
 * 4. Stop on timeout or next polling frame
 * 
 * This achieves "probabilistic collision avoidance" through statistical likelihood
 * rather than precise timing.
 * 
 * NOTE: This code runs in the com.android.nfc process context.
 */
public class SprayController {
    
    private static final String TAG = "HcefHook.SprayCtrl";
    
    // Spray timing parameters (all in milliseconds)
    private static final long SPRAY_INTERVAL_MS = 2;     // Send every 2ms
    private static final long SPRAY_DURATION_MS = 20;    // Total spray window
    private static final int MAX_TRANSMISSIONS = 10;      // Max attempts per spray cycle
    
    // State management
    private static final AtomicBoolean sprayActive = new AtomicBoolean(false);
    private static final AtomicInteger transmissionCount = new AtomicInteger(0);
    private static Handler sprayHandler = null;
    private static Runnable sprayRunnable = null;
    
    // Current spray payload
    private static byte[] currentSensfRes = null;
    
    // Reference to NativeNfcManager for transmission
    private static Object nativeNfcManagerInstance = null;
    private static Method transceiveMethod = null;
    
    /**
     * Set the NativeNfcManager instance for transmission
     * Should be called when SendRawFrameHook captures the instance
     */
    public static void setNativeNfcManager(Object instance, Method method) {
        nativeNfcManagerInstance = instance;
        transceiveMethod = method;
        XposedBridge.log(TAG + ": NativeNfcManager configured for spray mode");
    }
    
    /**
     * Check if spray mode is currently active
     */
    public static boolean isSprayActive() {
        return sprayActive.get();
    }
    
    /**
     * Start spray transmission for a SENSF_RES
     * 
     * @param sensfRes The SENSF_RES frame to continuously transmit
     */
    public static void startSpray(byte[] sensfRes) {
        if (sensfRes == null || sensfRes.length < 18) {
            XposedBridge.log(TAG + ": Invalid SENSF_RES, cannot start spray");
            return;
        }
        
        // Stop any existing spray
        stopSpray();
        
        // Enable bypass mode in native hooks
        try {
            if (DobbyHooks.isLoaded()) {
                DobbyHooks.enableSprayMode();
            }
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Warning - could not enable native spray mode: " + e.getMessage());
        }
        
        // Enable state bypass in Java hooks
        NfaStateHook.spoofListenActiveState();
        
        currentSensfRes = sensfRes;
        sprayActive.set(true);
        transmissionCount.set(0);
        
        XposedBridge.log(TAG + ": *** SPRAY MODE STARTED ***");
        XposedBridge.log(TAG + ": Payload: " + SensfResBuilder.toHexString(sensfRes));
        XposedBridge.log(TAG + ": Will transmit every " + SPRAY_INTERVAL_MS + "ms for " + SPRAY_DURATION_MS + "ms");
        
        // Initialize handler if needed
        if (sprayHandler == null) {
            try {
                sprayHandler = new Handler(Looper.getMainLooper());
            } catch (Exception e) {
                // If main looper not available, try creating new handler thread
                XposedBridge.log(TAG + ": Main looper not available, spray mode will be synchronous");
                // Fall back to immediate single transmission
                performTransmission();
                stopSpray();
                return;
            }
        }
        
        // Create spray runnable
        sprayRunnable = new Runnable() {
            private long startTime = System.currentTimeMillis();
            
            @Override
            public void run() {
                if (!sprayActive.get()) {
                    return;  // Spray was stopped externally
                }
                
                long elapsed = System.currentTimeMillis() - startTime;
                int count = transmissionCount.get();
                
                // Check termination conditions
                if (elapsed >= SPRAY_DURATION_MS || count >= MAX_TRANSMISSIONS) {
                    XposedBridge.log(TAG + ": Spray cycle complete - elapsed=" + elapsed + 
                                   "ms, transmissions=" + count);
                    stopSpray();
                    return;
                }
                
                // Perform transmission
                boolean success = performTransmission();
                
                if (success) {
                    transmissionCount.incrementAndGet();
                }
                
                // Schedule next transmission
                if (sprayActive.get() && sprayHandler != null) {
                    sprayHandler.postDelayed(this, SPRAY_INTERVAL_MS);
                }
            }
        };
        
        // Start spray cycle
        sprayHandler.post(sprayRunnable);
    }
    
    /**
     * Stop spray transmission
     */
    public static void stopSpray() {
        if (!sprayActive.get()) {
            return;  // Already stopped
        }
        
        sprayActive.set(false);
        
        // Cancel pending transmissions
        if (sprayHandler != null && sprayRunnable != null) {
            sprayHandler.removeCallbacks(sprayRunnable);
        }
        
        // Restore state
        NfaStateHook.restoreState();
        
        // Disable spray mode in native hooks
        try {
            if (DobbyHooks.isLoaded()) {
                DobbyHooks.disableSprayMode();
            }
        } catch (Exception e) {
            // Ignore
        }
        
        int finalCount = transmissionCount.get();
        XposedBridge.log(TAG + ": *** SPRAY MODE STOPPED ***");
        XposedBridge.log(TAG + ": Total transmissions: " + finalCount);
        
        currentSensfRes = null;
        transmissionCount.set(0);
    }
    
    /**
     * Perform a single transmission of the current SENSF_RES
     * 
     * @return true if transmission succeeded
     */
    private static boolean performTransmission() {
        if (currentSensfRes == null) {
            return false;
        }
        
        try {
            if (nativeNfcManagerInstance != null && transceiveMethod != null) {
                int[] responseLen = new int[1];
                
                // Call native transceive method
                byte[] response = (byte[]) transceiveMethod.invoke(
                    nativeNfcManagerInstance, currentSensfRes, false, responseLen);
                
                int count = transmissionCount.get();
                if (count % 3 == 0) {  // Log every 3rd transmission to avoid spam
                    XposedBridge.log(TAG + ": Transmission #" + (count + 1) + " - " + 
                                   (response != null ? "OK" : "failed"));
                }
                
                return response != null;
            } else {
                if (transmissionCount.get() == 0) {  // Log only once
                    XposedBridge.log(TAG + ": Cannot transmit - NativeNfcManager not available");
                }
                return false;
            }
        } catch (Exception e) {
            if (transmissionCount.get() == 0) {  // Log only once
                XposedBridge.log(TAG + ": Transmission error: " + e.getMessage());
            }
            return false;
        }
    }
    
    /**
     * Trigger single-shot SENSF_RES injection (non-spray mode)
     * 
     * @param sensfRes The SENSF_RES frame to transmit once
     * @return true if transmission succeeded
     */
    public static boolean injectOnce(byte[] sensfRes) {
        if (sensfRes == null || sensfRes.length < 18) {
            XposedBridge.log(TAG + ": Invalid SENSF_RES for injection");
            return false;
        }
        
        XposedBridge.log(TAG + ": Single-shot injection: " + SensfResBuilder.toHexString(sensfRes));
        
        // Enable bypass temporarily
        NfaStateHook.spoofListenActiveState();
        
        try {
            if (nativeNfcManagerInstance != null && transceiveMethod != null) {
                int[] responseLen = new int[1];
                byte[] response = (byte[]) transceiveMethod.invoke(
                    nativeNfcManagerInstance, sensfRes, false, responseLen);
                
                boolean success = response != null;
                XposedBridge.log(TAG + ": Injection " + (success ? "succeeded" : "failed"));
                return success;
            } else {
                XposedBridge.log(TAG + ": Cannot inject - NativeNfcManager not available");
                return false;
            }
        } catch (Exception e) {
            XposedBridge.log(TAG + ": Injection error: " + e.getMessage());
            return false;
        } finally {
            // Restore state
            NfaStateHook.restoreState();
        }
    }
    
    /**
     * Get spray statistics
     */
    public static String getStats() {
        return String.format("Spray Active: %s, Transmissions: %d",
            sprayActive.get() ? "YES" : "NO",
            transmissionCount.get());
    }
}
