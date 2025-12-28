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
import app.aoki.yuki.hcefhook.xposed.hooks.SprayController;

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
    private CheckBox autoInjectCheck;
    private CheckBox bypassCheck;
    private TextView statsText;
    
    // Observe Mode controls
    private Button observeModeToggleButton;
    private CheckBox sprayModeCheck;
    
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
        
        appendLog("INFO", "MainActivity.onCreate() - Starting initialization");
        
        // Initialize IPC client
        ipcClient = new IpcClient(this);
        appendLog("DEBUG", "IPC client initialized");
        
        initViews();
        setupLogReceiver();
        setupStatusUpdater();
        loadSavedConfig();
        
        // CRITICAL INTEGRATION: Initialize ObserveModeManager
        initializeObserveModeManager();
        
        updateStatus();
        
        appendLog("INFO", "HCE-F Hook PoC started");
        appendLog("INFO", "Device: " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ")");
        appendLog("INFO", "Waiting for hook activation...");
    }
    
    /**
     * Initialize ObserveModeManager and set up callback
     * CRITICAL INTEGRATION: Connects MainActivity to ObserveModeManager
     */
    private void initializeObserveModeManager() {
        appendLog("INFO", "=== Initializing Observe Mode Manager ===");
        
        boolean success = ObserveModeManager.initialize(this);
        if (success) {
            appendLog("INFO", "✓ ObserveModeManager initialized successfully");
            
            // CRITICAL: Register callback for SENSF_REQ detection
            ObserveModeManager.setSensfReqCallback((reqData, systemCode) -> {
                runOnUiThread(() -> {
                    String msg = String.format("*** SENSF_REQ Detected via ObserveModeManager ***\n  SystemCode: 0x%04X\n  Data: %s",
                        systemCode, SensfResBuilder.toHexString(reqData));
                    appendLog("DETECT", msg);
                    
                    Toast.makeText(this, "SENSF_REQ SC=0x" + 
                        Integer.toHexString(systemCode).toUpperCase(), Toast.LENGTH_LONG).show();
                    
                    // Trigger SENSF_RES injection based on mode
                    if (autoInjectCheck != null && autoInjectCheck.isChecked()) {
                        appendLog("INFO", "Auto-inject enabled - preparing SENSF_RES");
                        
                        try {
                            String idmHex = idmInput.getText().toString().replace(" ", "").toUpperCase();
                            String pmmHex = pmmInput.getText().toString().replace(" ", "").toUpperCase();
                            
                            byte[] idm = hexToBytes(idmHex);
                            byte[] pmm = hexToBytes(pmmHex);
                            
                            byte[] sensfRes = new SensfResBuilder()
                                .setIdm(idm)
                                .setPmm(pmm)
                                .build();
                            
                            // Check if spray mode is enabled
                            if (sprayModeCheck != null && sprayModeCheck.isChecked()) {
                                appendLog("INFO", "Spray mode enabled - using continuous transmission");
                                // Note: Spray mode is triggered via hooks in android.nfc process
                                // We queue the injection via IPC
                                ipcClient.queueInjection(sensfRes);
                            } else {
                                appendLog("INFO", "Single-shot mode - queuing injection");
                                ipcClient.queueInjection(sensfRes);
                            }
                        } catch (Exception e) {
                            appendLog("ERROR", "Failed to prepare SENSF_RES: " + e.getMessage());
                        }
                    } else {
                        appendLog("INFO", "Auto-inject disabled - user action required");
                    }
                });
            });
            
            appendLog("INFO", "✓ SENSF_REQ callback registered");
        } else {
            appendLog("ERROR", "✗ ObserveModeManager initialization failed");
            appendLog("WARN", "  Observe Mode features may not work");
        }
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
