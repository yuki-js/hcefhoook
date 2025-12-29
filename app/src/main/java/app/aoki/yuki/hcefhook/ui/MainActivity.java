package app.aoki.yuki.hcefhook.ui;

import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import app.aoki.yuki.hcefhook.R;
import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.core.LogReceiver;
import app.aoki.yuki.hcefhook.core.SensfResBuilder;
import app.aoki.yuki.hcefhook.ipc.HookIpcProvider;
import app.aoki.yuki.hcefhook.ipc.IpcClient;
import app.aoki.yuki.hcefhook.observemode.ObserveModeManager;

/**
 * Main activity for HCE-F Hook PoC
 * 
 * Features:
 * - Real-time status display (Xposed active, hook status)
 * - Log output from hooks via IPC
 * - SENSF_REQ detection notifications
 * - SENSF_RES configuration and injection controls
 * - Auto-inject toggle
 * - Manual injection trigger
 * - Statistics display
 * 
 * NOTE: This Activity runs in the app's own process.
 * Communication with hooks (running in com.android.nfc) uses IPC.
 */
public class MainActivity extends AppCompatActivity implements LogReceiver.LogCallback {
    
    private static final String TAG = "HcefHook.MainActivity";
    private static final int STATUS_UPDATE_INTERVAL_MS = 2000;
    
    // UI Components
    private TextView statusText;
    private TextView logText;
    private ScrollView logScrollView;
    private EditText idmInput;
    private EditText pmmInput;
    private Button testButton;
    private Button injectButton;
    private Button clearButton;
    private Button observeModeButton;
    private Button spray100Button;
    private CheckBox autoInjectCheck;
    private CheckBox bypassCheck;
    private TextView statsText;
    
    // Observe Mode Manager (no reflection, clean implementation)
    private ObserveModeManager observeModeManager;
    
    // IPC Client for communicating with hooks
    private IpcClient ipcClient;
    
    // Log handling
    private LogReceiver logReceiver;
    private StringBuilder logBuffer = new StringBuilder();
    private SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
    
    // Status update handler
    private Handler statusHandler;
    private Runnable statusUpdateRunnable;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Initialize IPC client
        ipcClient = new IpcClient(this);
        
        // Initialize ObserveModeManager (no reflection, clean API)
        observeModeManager = new ObserveModeManager(this);
        
        // Note: Polling frame data is delivered via IPC (LogBroadcaster)
        // not via this callback, to avoid reflection in MainActivity
        // The onSensfDetected() method handles the parsed data
        
        // Initialize views FIRST before any logging
        initViews();
        setupLogReceiver();
        setupStatusUpdater();
        loadSavedConfig();
        
        // Now safe to log after views are initialized
        appendLog("INFO", "MainActivity.onCreate() - Starting initialization");
        appendLog("DEBUG", "IPC client initialized");
        
        updateStatus();
        
        appendLog("INFO", "HCE-F Hook PoC started");
        appendLog("INFO", "Device: " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ")");
        appendLog("INFO", "Waiting for Xposed hook activation...");
        appendLog("WARN", "Observe Mode control happens via Xposed hooks in com.android.nfc process");
    }
    
    private void initViews() {
        statusText = findViewById(R.id.statusText);
        logText = findViewById(R.id.logText);
        logScrollView = findViewById(R.id.logScrollView);
        idmInput = findViewById(R.id.idmInput);
        pmmInput = findViewById(R.id.pmmInput);
        testButton = findViewById(R.id.testButton);
        injectButton = findViewById(R.id.injectButton);
        clearButton = findViewById(R.id.clearButton);
        observeModeButton = findViewById(R.id.observeModeButton);
        autoInjectCheck = findViewById(R.id.autoInjectCheck);
        bypassCheck = findViewById(R.id.bypassCheck);
        statsText = findViewById(R.id.statsText);
        
        logText.setMovementMethod(new ScrollingMovementMethod());
        
        // Set default values
        idmInput.setText(bytesToHex(Constants.DEFAULT_IDM));
        pmmInput.setText(bytesToHex(Constants.DEFAULT_PMM));
        
        // Test button - build and validate SENSF_RES
        testButton.setOnClickListener(v -> testSensfResGeneration());
        
        // Inject button - queue SENSF_RES for injection
        if (injectButton != null) {
            injectButton.setOnClickListener(v -> queueManualInjection());
        }
        
        // Clear log button
        if (clearButton != null) {
            clearButton.setOnClickListener(v -> clearLog());
        }
        
        // Observe Mode toggle button
        if (observeModeButton != null) {
            observeModeButton.setOnClickListener(v -> toggleObserveMode());
        }
        
        // Spray 100x button
        spray100Button = findViewById(R.id.spray100Button);
        if (spray100Button != null) {
            spray100Button.setOnClickListener(v -> sprayFrames100x());
        }
        
        // Auto-inject checkbox
        if (autoInjectCheck != null) {
            autoInjectCheck.setOnCheckedChangeListener((buttonView, isChecked) -> {
                ipcClient.setAutoInject(isChecked);
                appendLog("CONFIG", "Auto-inject " + (isChecked ? "enabled" : "disabled"));
            });
        }
        
        // Bypass checkbox
        if (bypassCheck != null) {
            bypassCheck.setOnCheckedChangeListener((buttonView, isChecked) -> {
                ipcClient.setBypassEnabled(isChecked);
                appendLog("CONFIG", "State bypass " + (isChecked ? "enabled" : "disabled"));
            });
        }
    }
    
    private void setupLogReceiver() {
        logReceiver = new LogReceiver();
        LogReceiver.setCallback(this);
        
        IntentFilter filter = new IntentFilter();
        filter.addAction(Constants.ACTION_LOG_ENTRY);
        filter.addAction(Constants.ACTION_SENSF_DETECTED);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(logReceiver, filter, RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(logReceiver, filter);
        }
    }
    
    private void setupStatusUpdater() {
        statusHandler = new Handler(Looper.getMainLooper());
        statusUpdateRunnable = new Runnable() {
            @Override
            public void run() {
                updateStatus();
                statusHandler.postDelayed(this, STATUS_UPDATE_INTERVAL_MS);
            }
        };
    }
    
    private void loadSavedConfig() {
        try {
            // Load IDm/PMm from IPC if set
            byte[] savedIdm = ipcClient.getIdm();
            byte[] savedPmm = ipcClient.getPmm();
            
            if (savedIdm != null && savedIdm.length == 8) {
                idmInput.setText(bytesToHex(savedIdm));
            }
            if (savedPmm != null && savedPmm.length == 8) {
                pmmInput.setText(bytesToHex(savedPmm));
            }
            
            // Load toggle states
            if (autoInjectCheck != null) {
                autoInjectCheck.setChecked(ipcClient.isAutoInjectEnabled());
            }
            if (bypassCheck != null) {
                bypassCheck.setChecked(ipcClient.isBypassEnabled());
            }
        } catch (Exception e) {
            appendLog("WARN", "Could not load saved config: " + e.getMessage());
        }
    }
    
    private void updateStatus() {
        StringBuilder status = new StringBuilder();
        
        try {
            Map<String, String> hookStatus = ipcClient.getStatus();
            
            boolean hookActive = "true".equals(hookStatus.get("hook_active"));
            boolean bypassEnabled = "true".equals(hookStatus.get("bypass_enabled"));
            boolean autoInject = "true".equals(hookStatus.get("auto_inject"));
            String injectionCount = hookStatus.getOrDefault("injection_count", "0");
            String pendingInjections = hookStatus.getOrDefault("pending_injections", "0");
            
            status.append("=== HCE-F Hook Status ===\n");
            status.append(String.format("• Xposed Hook: %s\n", hookActive ? "Active ✓" : "Inactive ✗"));
            status.append(String.format("• State Bypass: %s\n", bypassEnabled ? "ON" : "OFF"));
            status.append(String.format("• Auto-Inject: %s\n", autoInject ? "ON" : "OFF"));
            status.append(String.format("• Injections: %s\n", injectionCount));
            status.append(String.format("• Pending: %s\n", pendingInjections));
            status.append("• Target: SENSF_REQ (SC=FFFF)");
            
            // Update stats text if available
            if (statsText != null) {
                statsText.setText(String.format("Injections: %s | Pending: %s", 
                    injectionCount, pendingInjections));
            }
            
        } catch (Exception e) {
            status.append("=== HCE-F Hook Status ===\n");
            status.append("• Hook Status: Unknown\n");
            status.append("• Error: " + e.getMessage() + "\n");
            status.append("• Target: SENSF_REQ (SC=FFFF)");
        }
        
        statusText.setText(status.toString());
    }
    
    private void testSensfResGeneration() {
        appendLog("INFO", "Testing SENSF_RES generation...");
        
        try {
            String idmHex = idmInput.getText().toString().replace(" ", "").toUpperCase();
            String pmmHex = pmmInput.getText().toString().replace(" ", "").toUpperCase();
            
            byte[] idm = hexToBytes(idmHex);
            byte[] pmm = hexToBytes(pmmHex);
            
            if (idm.length != 8 || pmm.length != 8) {
                appendLog("ERROR", "IDm and PMm must be exactly 8 bytes each");
                Toast.makeText(this, "IDm/PMm must be 8 bytes", Toast.LENGTH_SHORT).show();
                return;
            }
            
            byte[] sensfRes = new SensfResBuilder()
                .setIdm(idm)
                .setPmm(pmm)
                .build();
            
            appendLog("INFO", "SENSF_RES built successfully:");
            appendLog("DATA", "  " + SensfResBuilder.toHexString(sensfRes));
            appendLog("INFO", "  Length: " + sensfRes.length + " bytes");
            appendLog("INFO", "  IDm: " + idmHex);
            appendLog("INFO", "  PMm: " + pmmHex);
            
            // Save to IPC config
            ipcClient.setIdm(idm);
            ipcClient.setPmm(pmm);
            appendLog("CONFIG", "IDm/PMm saved to configuration");
            
            Toast.makeText(this, "SENSF_RES valid (" + sensfRes.length + " bytes)", 
                Toast.LENGTH_SHORT).show();
            
        } catch (Exception e) {
            appendLog("ERROR", "Failed to build SENSF_RES: " + e.getMessage());
            Toast.makeText(this, "Invalid input", Toast.LENGTH_SHORT).show();
        }
    }
    
    private void queueManualInjection() {
        appendLog("INFO", "Queueing manual SENSF_RES injection...");
        
        try {
            String idmHex = idmInput.getText().toString().replace(" ", "").toUpperCase();
            String pmmHex = pmmInput.getText().toString().replace(" ", "").toUpperCase();
            
            byte[] idm = hexToBytes(idmHex);
            byte[] pmm = hexToBytes(pmmHex);
            
            if (idm.length != 8 || pmm.length != 8) {
                appendLog("ERROR", "IDm and PMm must be exactly 8 bytes each");
                return;
            }
            
            byte[] sensfRes = new SensfResBuilder()
                .setIdm(idm)
                .setPmm(pmm)
                .build();
            
            // Queue via IPC
            boolean success = ipcClient.queueInjection(sensfRes);
            
            if (success) {
                appendLog("INFO", "SENSF_RES queued for injection");
                appendLog("DATA", "  " + SensfResBuilder.toHexString(sensfRes));
                Toast.makeText(this, "Injection queued", Toast.LENGTH_SHORT).show();
            } else {
                appendLog("ERROR", "Failed to queue injection");
                Toast.makeText(this, "Queue failed", Toast.LENGTH_SHORT).show();
            }
            
        } catch (Exception e) {
            appendLog("ERROR", "Injection queue error: " + e.getMessage());
        }
    }
    
    // LogReceiver.LogCallback implementation
    
    @Override
    public void onLogReceived(String message, int level, long timestamp) {
        String levelStr;
        switch (level) {
            case Constants.LOG_DEBUG: levelStr = "DEBUG"; break;
            case Constants.LOG_INFO: levelStr = "INFO"; break;
            case Constants.LOG_WARN: levelStr = "WARN"; break;
            case Constants.LOG_ERROR: levelStr = "ERROR"; break;
            default: levelStr = "LOG"; break;
        }
        appendLog(levelStr, message);
    }
    
    @Override
    public void onSensfDetected(byte[] reqData, int systemCode) {
        String msg = String.format("*** SENSF_REQ Detected ***\n  SystemCode: 0x%04X\n  Data: %s",
            systemCode, SensfResBuilder.toHexString(reqData));
        appendLog("DETECT", msg);
        
        // Update status to show detection
        runOnUiThread(() -> {
            Toast.makeText(this, "SENSF_REQ detected! SC=0x" + 
                Integer.toHexString(systemCode).toUpperCase(), Toast.LENGTH_LONG).show();
            updateStatus();
            
            // CRITICAL: Auto-inject SENSF_RES if enabled
            if (autoInjectCheck != null && autoInjectCheck.isChecked()) {
                appendLog("INFO", "Auto-inject enabled - preparing SENSF_RES");
                
                try {
                    String idmHex = idmInput.getText().toString().replace(" ", "").toUpperCase();
                    String pmmHex = pmmInput.getText().toString().replace(" ", "").toUpperCase();
                    
                    byte[] idm = hexToBytes(idmHex);
                    byte[] pmm = hexToBytes(pmmHex);
                    
                    if (idm.length != 8 || pmm.length != 8) {
                        appendLog("ERROR", "IDm and PMm must be exactly 8 bytes each");
                        return;
                    }
                    
                    byte[] sensfRes = new SensfResBuilder()
                        .setIdm(idm)
                        .setPmm(pmm)
                        .build();
                    
                    // Queue injection via IPC - hook will decide spray vs single-shot
                    // based on DobbyHooks.isSprayModeEnabled()
                    appendLog("INFO", "Queuing SENSF_RES injection");
                    boolean success = ipcClient.queueInjection(sensfRes);
                    
                    if (success) {
                        appendLog("INFO", "SENSF_RES queued successfully");
                    } else {
                        appendLog("ERROR", "Failed to queue SENSF_RES");
                    }
                } catch (Exception e) {
                    appendLog("ERROR", "Failed to prepare SENSF_RES: " + e.getMessage());
                }
            } else {
                appendLog("INFO", "Auto-inject disabled - user action required");
            }
        });
    }
    
    private void appendLog(String level, String message) {
        final String timestamp = timeFormat.format(new Date());
        final String logLine = String.format("[%s] %s: %s\n", timestamp, level, message);
        
        runOnUiThread(() -> {
            logBuffer.append(logLine);
            
            // Limit log size
            if (logBuffer.length() > 50000) {
                logBuffer.delete(0, 10000);
            }
            
            logText.setText(logBuffer.toString());
            
            // Auto-scroll to bottom
            logScrollView.post(() -> logScrollView.fullScroll(View.FOCUS_DOWN));
        });
    }
    
    private void clearLog() {
        logBuffer.setLength(0);
        logText.setText("");
        appendLog("INFO", "Log cleared");
    }
    
    /**
     * Toggle Observe Mode on/off
     * 
     * Uses ObserveModeManager for clean, reflection-free implementation.
     * The manager handles IPC communication with Xposed hooks which call
     * the official NfcService.setObserveMode() method.
     */
    private void toggleObserveMode() {
        boolean currentState = observeModeManager.isObserveModeEnabled();
        boolean newState = !currentState;
        
        if (newState) {
            appendLog("INFO", "=== ENABLING OBSERVE MODE ===");
            appendLog("INFO", "Using ObserveModeManager (no reflection)");
            
            boolean success = observeModeManager.enableObserveMode();
            
            if (success) {
                appendLog("INFO", "✓ Observe Mode enabled successfully");
                
                // Update button UI
                if (observeModeButton != null) {
                    observeModeButton.setText("Disable Observe Mode");
                    observeModeButton.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(
                            getResources().getColor(R.color.observe_mode_enabled, null)));
                }
                
                Toast.makeText(this, "Observe Mode ENABLED", Toast.LENGTH_SHORT).show();
            } else {
                appendLog("ERROR", "✗ Failed to enable Observe Mode");
                Toast.makeText(this, "Observe Mode Enable FAILED", Toast.LENGTH_SHORT).show();
            }
            
        } else {
            appendLog("INFO", "=== DISABLING OBSERVE MODE ===");
            
            boolean success = observeModeManager.disableObserveMode();
            
            if (success) {
                appendLog("INFO", "✓ Observe Mode disabled successfully");
                
                // Update button UI
                if (observeModeButton != null) {
                    observeModeButton.setText("Enable Observe Mode");
                    observeModeButton.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(
                            getResources().getColor(R.color.observe_mode_disabled, null)));
                }
                
                Toast.makeText(this, "Observe Mode DISABLED", Toast.LENGTH_SHORT).show();
            } else {
                appendLog("ERROR", "✗ Failed to disable Observe Mode");
                Toast.makeText(this, "Observe Mode Disable FAILED", Toast.LENGTH_SHORT).show();
            }
        }
    }
    
    /**
     * Spray 100 SENSF_RES frames with 3ms interval
     * 
     * This implements the "spray strategy" to compensate for the inability
     * to meet FeliCa's 2.4ms timing constraint in software.
     * 
     * IDm = 114514... (custom), PMm = FFFFFF... (wildcard)
     */
    private void sprayFrames100x() {
        appendLog("INFO", "=== SPRAY MODE: 100 SENSF_RES frames @ 3ms interval ===");
        
        // Get IDm from input or use default spray IDm
        String idmHex = idmInput.getText().toString().trim();
        if (idmHex.isEmpty() || idmHex.length() != 16) {
            // Default spray IDm: 114514...
            idmHex = "1145141919810000";
        }
        
        // PMm = FFFFFFFFFFFFFFFF for spray mode
        String pmmHex = "FFFFFFFFFFFFFFFF";
        
        byte[] idm = hexToBytes(idmHex);
        byte[] pmm = hexToBytes(pmmHex);
        
        appendLog("DEBUG", "IDm: " + idmHex);
        appendLog("DEBUG", "PMm: " + pmmHex);
        
        // Build SENSF_RES packet: [Length][0x01][IDm 8B][PMm 8B]
        byte[] sensfRes = new byte[18];
        sensfRes[0] = 18; // Length
        sensfRes[1] = 0x01; // Response code
        System.arraycopy(idm, 0, sensfRes, 2, 8);
        System.arraycopy(pmm, 0, sensfRes, 10, 8);
        
        final int SPRAY_COUNT = 100;
        final int SPRAY_INTERVAL_MS = 3;
        
        // Disable UI during spray
        spray100Button.setEnabled(false);
        spray100Button.setText("Spraying...");
        
        // Execute spray in background thread
        new Thread(() -> {
            long startTime = System.currentTimeMillis();
            int successCount = 0;
            int failCount = 0;
            
            appendLogOnUiThread("INFO", "Starting spray: " + SPRAY_COUNT + " frames");
            
            for (int i = 0; i < SPRAY_COUNT; i++) {
                try {
                    // Send raw frame via IPC (or direct call if available)
                    boolean success = ipcClient.sendRawFrame(sensfRes);
                    
                    if (success) {
                        successCount++;
                    } else {
                        failCount++;
                    }
                    
                    // Log progress every 10 frames
                    if ((i + 1) % 10 == 0) {
                        final int current = i + 1;
                        final int suc = successCount;
                        final int fail = failCount;
                        runOnUiThread(() -> appendLog("SPRAY", "Progress: " + current + "/" + SPRAY_COUNT + 
                            " (OK: " + suc + ", FAIL: " + fail + ")"));
                    }
                    
                    // Sleep between frames
                    if (i < SPRAY_COUNT - 1) {
                        Thread.sleep(SPRAY_INTERVAL_MS);
                    }
                } catch (InterruptedException e) {
                    appendLogOnUiThread("ERROR", "Spray interrupted at frame " + i);
                    break;
                } catch (Exception e) {
                    failCount++;
                    appendLogOnUiThread("ERROR", "Frame " + i + " error: " + e.getMessage());
                }
            }
            
            long elapsed = System.currentTimeMillis() - startTime;
            final int finalSuccess = successCount;
            final int finalFail = failCount;
            final long finalElapsed = elapsed;
            
            runOnUiThread(() -> {
                appendLog("INFO", "=== SPRAY COMPLETE ===");
                appendLog("INFO", "Total time: " + finalElapsed + "ms");
                appendLog("INFO", "Success: " + finalSuccess + ", Fail: " + finalFail);
                
                // Re-enable button
                spray100Button.setEnabled(true);
                spray100Button.setText("🔥 Spray 100x SENSF_RES (3ms interval)");
                
                Toast.makeText(MainActivity.this, 
                    "Spray complete: " + finalSuccess + "/" + SPRAY_COUNT + " OK",
                    Toast.LENGTH_SHORT).show();
            });
        }).start();
    }
    
    private void appendLogOnUiThread(String level, String message) {
        runOnUiThread(() -> appendLog(level, message));
    }
    
    // Utility methods
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        // Start status updates
        statusHandler.post(statusUpdateRunnable);
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        // Stop status updates
        statusHandler.removeCallbacks(statusUpdateRunnable);
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (logReceiver != null) {
            unregisterReceiver(logReceiver);
        }
        statusHandler.removeCallbacksAndMessages(null);
    }
}
