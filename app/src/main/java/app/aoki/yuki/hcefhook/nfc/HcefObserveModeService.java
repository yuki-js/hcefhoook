package app.aoki.yuki.hcefhook.nfc;

import android.content.Intent;
import android.nfc.cardemulation.HostNfcFService;
import android.os.Bundle;
import android.util.Log;

/**
 * HCE-F Service for Observe Mode
 * 
 * This is the CORRECT way to implement Observe Mode in Android 15+.
 * 
 * HOW IT WORKS:
 * =============
 * 1. This service extends HostNfcFService
 * 2. Declared in AndroidManifest with polling loop filters
 * 3. When service is enabled, system automatically calls setObserveModeEnabled(true)
 * 4. Polling frames (including SENSF_REQ with SC=FFFF) are delivered via onPollingLoopDetected()
 * 5. When service is disabled, system calls setObserveModeEnabled(false)
 * 
 * NO XPOSED HOOKS NEEDED FOR OBSERVE MODE!
 * 
 * Reference:
 * - https://github.com/kormax/android-observe-mode-demo
 * - https://developer.android.com/develop/connectivity/nfc/hce
 * - Android 15 NFC API documentation
 */
public class HcefObserveModeService extends HostNfcFService {
    
    private static final String TAG = "HcefHook.ObserveService";
    
    // Broadcast action for sending frames to UI
    public static final String ACTION_POLLING_FRAME = "app.aoki.yuki.hcefhook.POLLING_FRAME";
    public static final String EXTRA_FRAME_TYPE = "frame_type";
    public static final String EXTRA_FRAME_DATA = "frame_data";
    public static final String EXTRA_FRAME_TIMESTAMP = "frame_timestamp";
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "=== HCE-F Observe Mode Service Created ===");
        Log.i(TAG, "System will automatically enable Observe Mode");
        Log.i(TAG, "eSE will be silenced - no auto-response to SENSF_REQ");
    }
    
    @Override
    public void onDestroy() {
        Log.i(TAG, "=== HCE-F Observe Mode Service Destroyed ===");
        Log.i(TAG, "System will automatically disable Observe Mode");
        super.onDestroy();
    }
    
    /**
     * Called when NFC field is detected (poll detected)
     * 
     * This is the OLD HCE-F callback - NOT used in Observe Mode
     */
    @Override
    public byte[] processNfcFPacket(byte[] commandPacket, Bundle extras) {
        Log.d(TAG, "processNfcFPacket called (should not happen in Observe Mode)");
        // In Observe Mode, this should NOT be called
        // Polling frames go to onPollingLoopDetected() instead
        return null;
    }
    
    /**
     * Called when service is deactivated
     * Required abstract method from HostNfcFService
     */
    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "Service deactivated: reason=" + reason);
    }
    
    /**
     * Called when polling loop is detected (Observe Mode callback)
     * 
     * THIS IS THE KEY METHOD FOR OBSERVE MODE!
     * 
     * NOTE: This method is only available in Android 15+ (API 35+).
     * For compatibility, we handle it via reflection or let the system call it directly.
     * 
     * The method signature from Android 15:
     * public void onPollingLoopDetected(List<PollingFrame> frames)
     * 
     * Since we can't reference PollingFrame class directly (it's Android 15+ only),
     * we use reflection to access frame data.
     * 
     * @param frames List of PollingFrame objects containing raw polling data
     */
    public void onPollingLoopDetected(java.util.List<?> frames) {
        Log.i(TAG, "=== POLLING LOOP DETECTED ===");
        Log.i(TAG, "Received " + frames.size() + " polling frames");
        
        for (Object frameObj : frames) {
            try {
                // Use reflection to access PollingFrame methods
                // PollingFrame has: int getType() and byte[] getData()
                java.lang.reflect.Method getType = frameObj.getClass().getMethod("getType");
                java.lang.reflect.Method getData = frameObj.getClass().getMethod("getData");
                
                int type = (Integer) getType.invoke(frameObj);
                byte[] data = (byte[]) getData.invoke(frameObj);
                
                Log.i(TAG, "=== RAW POLLING FRAME ===");
                Log.i(TAG, "Type: " + type);
                Log.i(TAG, "Data: " + bytesToHex(data));
                Log.i(TAG, "Length: " + data.length + " bytes");
                
                // Check if this is SENSF_REQ with SC=FFFF
                if (isSensfReq(data)) {
                    byte[] systemCode = extractSystemCode(data);
                    Log.i(TAG, "✓ SENSF_REQ detected!");
                    Log.i(TAG, "  System Code: " + bytesToHex(systemCode));
                    
                    if (systemCode.length == 2 && systemCode[0] == (byte)0xFF && systemCode[1] == (byte)0xFF) {
                        Log.i(TAG, "  ✓✓✓ SC=FFFF (Wildcard) - This is our target!");
                    }
                }
                
                // Broadcast frame to MainActivity for display
                Intent intent = new Intent(ACTION_POLLING_FRAME);
                intent.putExtra(EXTRA_FRAME_TYPE, type);
                intent.putExtra(EXTRA_FRAME_DATA, data);
                intent.putExtra(EXTRA_FRAME_TIMESTAMP, System.currentTimeMillis());
                sendBroadcast(intent);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to process polling frame: " + e.getMessage(), e);
            }
        }
    }
    
    /**
     * Check if frame is SENSF_REQ
     * Format: [Length] [Cmd:00] [SystemCode:2B] [RequestCode] [TSN]
     */
    private boolean isSensfReq(byte[] data) {
        if (data == null || data.length < 4) {
            return false;
        }
        // Check if command byte is 0x00 (SENSF_REQ)
        return data.length >= 2 && data[1] == 0x00;
    }
    
    /**
     * Extract system code from SENSF_REQ
     */
    private byte[] extractSystemCode(byte[] data) {
        if (data == null || data.length < 4) {
            return new byte[0];
        }
        // System code is at bytes 2-3
        byte[] sc = new byte[2];
        sc[0] = data[2];
        sc[1] = data[3];
        return sc;
    }
    
    /**
     * Convert bytes to hex string for logging
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}
