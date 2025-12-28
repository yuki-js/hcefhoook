package app.aoki.yuki.hcefhook.core;

/**
 * Constants for HCE-F Hook application
 */
public final class Constants {
    
    // Intent actions
    public static final String ACTION_LOG_ENTRY = "app.aoki.yuki.hcefhook.LOG_ENTRY";
    public static final String ACTION_SENSF_DETECTED = "app.aoki.yuki.hcefhook.SENSF_DETECTED";
    
    // Intent extras
    public static final String EXTRA_LOG_MESSAGE = "log_message";
    public static final String EXTRA_LOG_LEVEL = "log_level";
    public static final String EXTRA_LOG_TIMESTAMP = "log_timestamp";
    public static final String EXTRA_SENSF_REQ_DATA = "sensf_req_data";
    public static final String EXTRA_SYSTEM_CODE = "system_code";
    
    // Log levels
    public static final int LOG_DEBUG = 0;
    public static final int LOG_INFO = 1;
    public static final int LOG_WARN = 2;
    public static final int LOG_ERROR = 3;
    
    // NFC-F Constants
    public static final int SENSF_REQ_CMD = 0x00;
    public static final int SENSF_RES_CMD = 0x01;
    public static final int SYSTEM_CODE_WILDCARD = 0xFFFF;
    
    // Default IDm for injection (11 45 14 ...)
    // This is the test IDm specified in the requirements
    public static final byte[] DEFAULT_IDM = new byte[] {
        0x11, 0x45, 0x14, 0x19, 0x19, (byte)0x81, 0x00, 0x00
    };
    
    // Default PMm for injection (FF FF FF ...)
    public static final byte[] DEFAULT_PMM = new byte[] {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
    };
    
    // State constants from NFA layer
    public static final int NFA_DM_RFST_IDLE = 0x00;
    public static final int NFA_DM_RFST_DISCOVERY = 0x01;
    public static final int NFA_DM_RFST_W4_ALL_DISC = 0x02;
    public static final int NFA_DM_RFST_W4_HOST_SELECT = 0x03;
    public static final int NFA_DM_RFST_POLL_ACTIVE = 0x04;
    public static final int NFA_DM_RFST_LISTEN_ACTIVE = 0x05;
    public static final int NFA_DM_RFST_LISTEN_SLEEP = 0x06;

    // Spray strategy defaults for repeated SENSF_RES responses
    // (3 bursts spaced by 10ms to mirror NFC poll cadence while keeping bursts under ~30ms)
    public static final int SENSF_SPRAY_COUNT = 3;
    public static final long SENSF_SPRAY_INTERVAL_MS = 10L;
    
    private Constants() {
        // Prevent instantiation
    }
}
