# Migration Guide - PR Fix Observe Mode Architecture

## Overview

This guide helps developers migrate from the old architecture to the new improved architecture introduced in this PR.

---

## Breaking Changes

### 1. Observe Mode Control

#### Old Way (INCORRECT - Don't Use)
```java
// MainActivity.java
ObserveModeManager manager = new ObserveModeManager(this);
manager.enableObserveMode(); // ❌ REMOVED - Used IPC (wrong!)
```

#### New Way (CORRECT)
```java
// MainActivity.java  
// Step 1: Get NfcAdapter
NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);

// Step 2: Set app as preferred service (required for Android 15+)
CardEmulation cardEmulation = CardEmulation.getInstance(nfcAdapter);
ComponentName serviceName = new ComponentName(this, HcefObserveModeService.class);
cardEmulation.setPreferredService(this, serviceName);

// Step 3: Enable Observe Mode
Method m = nfcAdapter.getClass().getMethod("setObserveModeEnabled", boolean.class);
m.invoke(nfcAdapter, true);

// Update local state
observeModeManager.isObserveModeEnabled = true;
```

**Why the change?**
- Observe Mode is tied to Activity lifecycle
- Activity runs in app process with NfcAdapter access
- IPC-based delegation was architecturally incorrect
- Direct API calls are more reliable

---

### 2. IPC Communication

#### Old Way (REMOVED)
```java
// Using ContentProvider (BROKEN - couldn't receive on com.android.nfc side)
IpcClient client = new IpcClient(context);
String idm = client.getIdm(); // ❌ REMOVED - sync query
client.enableObserveMode();   // ❌ REMOVED - wrong architecture
```

#### New Way (Broadcast IPC)
```java
// Using BroadcastIpc (NEW - works bidirectionally)
BroadcastIpc ipc = new BroadcastIpc(context, "app.aoki.yuki.hcefhook");

// Set command handler for responses
ipc.setCommandHandler((commandType, data, sourceProcess) -> {
    if ("STATUS".equals(commandType)) {
        String idm = data.get("idm");
        String pmm = data.get("pmm");
        // Handle response
    }
});

ipc.register();

// Send async command
Map<String, String> cmdData = new HashMap<>();
cmdData.put("action", "get_status");
ipc.sendCommand("GET_STATUS", cmdData);
```

**Why the change?**
- ContentProvider couldn't receive broadcasts on com.android.nfc side
- Broadcast IPC works bidirectionally
- More reliable for cross-process communication
- Supports async communication pattern

---

### 3. Deprecated Method Removal

#### Removed from ObserveModeManager
```java
// ❌ All these methods are REMOVED:
manager.enableObserveMode();           // Use MainActivity direct control
manager.disableObserveMode();          // Use MainActivity direct control
manager.isObserveModeAvailable();      // Check NfcAdapter directly
manager.checkCurrentObserveModeState(); // Use isObserveModeEnabled()
```

#### Removed from IpcClient
```java
// ❌ These methods are REMOVED:
client.enableObserveMode();   // Use MainActivity direct control
client.disableObserveMode();  // Use MainActivity direct control
```

---

## Architecture Changes

### Before
```
MainActivity
    ↓ (IPC via ContentProvider)
XposedInit in com.android.nfc
    ↓
ObserveModeHook.setObserveModeEnabled()  // ❌ Wrong!
```

**Problems:**
- Can't get NfcAdapter in com.android.nfc process
- IPC adds unnecessary complexity
- Violates Android architecture principles

### After
```
MainActivity (app process)
    ↓ (Direct API call)
NfcAdapter.setObserveModeEnabled()  // ✓ Correct!

XposedInit in com.android.nfc
    ↓ (Passive monitoring only)
ObserveModeHook observes calls  // ✓ Passive observer
```

**Benefits:**
- Follows Android architecture best practices
- More reliable (direct API, no IPC overhead)
- Hooks are passive observers (as they should be)
- Proper Activity lifecycle management

---

## Code Migration Examples

### Example 1: Enable Observe Mode

**Before:**
```java
public void onEnableButtonClick(View v) {
    observeModeManager.enableObserveMode();  // ❌ IPC-based
}
```

**After:**
```java
public void onEnableButtonClick(View v) {
    try {
        // Get NfcAdapter
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        
        // Set preferred service
        CardEmulation ce = CardEmulation.getInstance(nfcAdapter);
        ComponentName svc = new ComponentName(this, HcefObserveModeService.class);
        ce.setPreferredService(this, svc);
        
        // Enable Observe Mode
        Method m = nfcAdapter.getClass().getMethod("setObserveModeEnabled", boolean.class);
        m.invoke(nfcAdapter, true);
        
        observeModeManager.isObserveModeEnabled = true;
        Toast.makeText(this, "Observe Mode Enabled", Toast.LENGTH_SHORT).show();
    } catch (Exception e) {
        Log.e(TAG, "Failed to enable Observe Mode", e);
        Toast.makeText(this, "Observe Mode Failed", Toast.LENGTH_SHORT).show();
    }
}
```

### Example 2: IPC Communication

**Before (ContentProvider):**
```java
IpcClient client = new IpcClient(context);
String status = client.getStatus(); // ❌ Synchronous, broken
```

**After (Broadcast IPC):**
```java
BroadcastIpc ipc = new BroadcastIpc(context, "app.aoki.yuki.hcefhook");

ipc.setCommandHandler((cmdType, data, source) -> {
    if ("STATUS".equals(cmdType)) {
        String status = data.get("status");
        // Use status asynchronously
    }
});

ipc.register();
ipc.sendCommand("GET_STATUS", new HashMap<>());
```

### Example 3: Checking Observe Mode State

**Before:**
```java
boolean available = observeModeManager.isObserveModeAvailable(); // ❌ Removed
boolean current = observeModeManager.checkCurrentObserveModeState(); // ❌ Removed
```

**After:**
```java
// Check if enabled (local state)
boolean enabled = observeModeManager.isObserveModeEnabled();

// Check NFC availability
NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);
boolean available = (nfcAdapter != null) && nfcAdapter.isEnabled();

// Verify via reflection (optional)
try {
    Method m = nfcAdapter.getClass().getMethod("isObserveModeEnabled");
    boolean actualState = (boolean) m.invoke(nfcAdapter);
} catch (Exception e) {
    // Observe Mode not supported on this device
}
```

---

## Native Hook Changes

### Dobby Removed

**Before:**
```java
DobbyHooks.enableSprayMode();  // ❌ Dobby-based (removed)
```

**After:**
```java
SprayController.startSpray(sensfRes);  // ✓ Pure Java
// OR use Frida (see DobbyHooks.java for Frida documentation)
```

**Migration:**
- Spray mode now pure Java implementation
- For native hooks, use Frida instead (DobbyHooks.java documents approach)
- No functional changes needed in most cases

---

## KernelSU Module

### Installation

**Before:**
```bash
# Old module structure
adb push kernelsu_module /sdcard/
# Install via KernelSU app
```

**After:**
```bash
# New MMT-Extended-Next structure
adb push hcefhook-module.zip /sdcard/
# Install via KernelSU/Magisk Manager
# Module now has proper installation scripts
```

**Changes:**
- Proper MMT-Extended-Next template structure
- Comprehensive `customize.sh` with logging
- Better error handling
- More robust installation process

---

## Testing Your Migration

### Verification Checklist

1. ✅ **Observe Mode Works**
   ```
   - Tap "Enable Observe Mode" button
   - Check logs for "Observe Mode ENABLED"
   - Verify: isObserveModeEnabled() = true
   ```

2. ✅ **IPC Communication Works**
   ```
   - Check logs for BroadcastIpc registration
   - Send test command
   - Verify response received
   ```

3. ✅ **No Deprecated Methods Used**
   ```
   grep -r "enableObserveMode\|disableObserveMode" yourcode/
   # Should find only new direct API calls
   ```

4. ✅ **Build Succeeds**
   ```bash
   ./gradlew clean assembleDebug
   # Should complete without errors
   ```

---

## Common Issues & Solutions

### Issue 1: "Caller not preferred NFC service"

**Problem:**
```
E/NfcService: setObserveMode() - Caller not preferred NFC service.
```

**Solution:**
```java
// MUST call setPreferredService() BEFORE setObserveModeEnabled()
CardEmulation ce = CardEmulation.getInstance(nfcAdapter);
ComponentName svc = new ComponentName(this, HcefObserveModeService.class);
ce.setPreferredService(this, svc);  // ← Add this!

// THEN enable Observe Mode
Method m = nfcAdapter.getClass().getMethod("setObserveModeEnabled", boolean.class);
m.invoke(nfcAdapter, true);
```

### Issue 2: IPC Not Receiving Messages

**Problem:**
Broadcast IPC not receiving messages

**Solution:**
```java
// 1. Ensure receiver is registered
ipc.register();

// 2. Set command handler BEFORE registering
ipc.setCommandHandler((cmdType, data, source) -> {
    Log.d(TAG, "Received: " + cmdType);
});
ipc.register();

// 3. Check IntentFilter actions match
// Sender: ACTION_COMMAND
// Receiver: filter.addAction(ACTION_COMMAND)
```

### Issue 3: NullPointerException on Startup

**Problem:**
```
NullPointerException: Attempt to invoke virtual method 'void android.widget.TextView.setText'
```

**Solution:**
```java
// Initialize views BEFORE IPC setup
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    
    initViews();  // ← FIRST
    setupBroadcastIpc();  // ← THEN IPC
}
```

---

## Additional Resources

- **CHANGELOG_PR.md** - Detailed change log
- **FINAL_WORK_SUMMARY.md** - Executive summary
- **scripts/verify_pr.sh** - Automated verification
- **DobbyHooks.java** - Frida usage documentation

---

## Questions?

If you encounter issues during migration:

1. Run verification script: `./scripts/verify_pr.sh`
2. Check build logs: `./gradlew clean assembleDebug`
3. Review example implementation in MainActivity.java (lines 518-640)
4. Check BroadcastIpc.java for IPC usage examples

---

**Last Updated:** 2025-12-30
**PR:** Fix Observe Mode Architecture
**Status:** All migrations tested and verified ✓
