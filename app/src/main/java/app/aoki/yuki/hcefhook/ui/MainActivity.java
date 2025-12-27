package app.aoki.yuki.hcefhook.ui;

import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import app.aoki.yuki.hcefhook.R;
import app.aoki.yuki.hcefhook.core.Constants;
import app.aoki.yuki.hcefhook.core.LogReceiver;
import app.aoki.yuki.hcefhook.core.SensfResBuilder;

/**
 * Main activity for HCE-F Hook PoC
 * 
 * Displays:
 * - Status of Xposed module
 * - Log output from hooks
 * - SENSF_REQ detection notifications
 * - SENSF_RES injection controls
 */
public class MainActivity extends AppCompatActivity implements LogReceiver.LogCallback {
    
    private static final String TAG = "HcefHook.MainActivity";
    
    private TextView statusText;
    private TextView logText;
    private ScrollView logScrollView;
    private EditText idmInput;
    private EditText pmmInput;
    private Button testButton;
    
    private LogReceiver logReceiver;
    private StringBuilder logBuffer = new StringBuilder();
    private SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        initViews();
        setupLogReceiver();
        updateStatus();
        
        appendLog("INFO", "HCE-F Hook PoC started");
        appendLog("INFO", "Device: " + Build.MODEL + " (Android " + Build.VERSION.RELEASE + ")");
    }
    
    private void initViews() {
        statusText = findViewById(R.id.statusText);
        logText = findViewById(R.id.logText);
        logScrollView = findViewById(R.id.logScrollView);
        idmInput = findViewById(R.id.idmInput);
        pmmInput = findViewById(R.id.pmmInput);
        testButton = findViewById(R.id.testButton);
        
        logText.setMovementMethod(new ScrollingMovementMethod());
        
        // Set default values
        idmInput.setText(bytesToHex(Constants.DEFAULT_IDM));
        pmmInput.setText(bytesToHex(Constants.DEFAULT_PMM));
        
        // Test button handler
        testButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                testSensfResGeneration();
            }
        });
        
        // Clear log button
        Button clearButton = findViewById(R.id.clearButton);
        if (clearButton != null) {
            clearButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    clearLog();
                }
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
    
    private void updateStatus() {
        StringBuilder status = new StringBuilder();
        status.append("Status:\n");
        status.append("• Xposed Module: ");
        status.append(isXposedActive() ? "Active ✓" : "Inactive ✗");
        status.append("\n• NFC Hooks: Waiting for activation...");
        status.append("\n• Target: SENSF_REQ (SC=FFFF)");
        
        statusText.setText(status.toString());
    }
    
    private boolean isXposedActive() {
        // Check if the Xposed module is active by looking for a preference set by the hook
        // The XposedInit hook sets this preference when it successfully hooks
        try {
            android.content.SharedPreferences prefs = getSharedPreferences(
                "hcef_hook_status", android.content.Context.MODE_PRIVATE);
            return prefs.getBoolean("xposed_active", false);
        } catch (Exception e) {
            return false;
        }
    }
    
    private void testSensfResGeneration() {
        appendLog("INFO", "Testing SENSF_RES generation...");
        
        try {
            String idmHex = idmInput.getText().toString().replace(" ", "");
            String pmmHex = pmmInput.getText().toString().replace(" ", "");
            
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
            
            appendLog("INFO", "SENSF_RES built successfully:");
            appendLog("DATA", "  " + SensfResBuilder.toHexString(sensfRes));
            appendLog("INFO", "  Length: " + sensfRes.length + " bytes");
            appendLog("INFO", "  IDm: " + bytesToHex(idm));
            appendLog("INFO", "  PMm: " + bytesToHex(pmm));
            
        } catch (Exception e) {
            appendLog("ERROR", "Failed to build SENSF_RES: " + e.getMessage());
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
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                statusText.setText("Status:\n• SENSF_REQ (SC=FFFF) DETECTED!\n• Attempting injection...");
            }
        });
    }
    
    private void appendLog(String level, String message) {
        final String timestamp = timeFormat.format(new Date());
        final String logLine = String.format("[%s] %s: %s\n", timestamp, level, message);
        
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                logBuffer.append(logLine);
                logText.setText(logBuffer.toString());
                
                // Auto-scroll to bottom
                logScrollView.post(new Runnable() {
                    @Override
                    public void run() {
                        logScrollView.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });
    }
    
    private void clearLog() {
        logBuffer.setLength(0);
        logText.setText("");
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
    protected void onDestroy() {
        super.onDestroy();
        if (logReceiver != null) {
            unregisterReceiver(logReceiver);
        }
    }
}
