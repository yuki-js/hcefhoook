# Observe Mode Implementation - CORRECT Architecture

## Critical Mistake Identified

The original implementation was **fundamentally wrong**. We were trying to manually control Observe Mode via Xposed hooks, which is NOT how Android's Observe Mode API works.

## The CORRECT Way (Android 15+)

### Architecture Overview

```
USER APP PROCESS (app.aoki.yuki.hcefhook):
├── HcefObserveModeService.java (extends HostNfcFService)
│   ├── Declared in AndroidManifest with polling-loop-filter
│   ├── System automatically calls setObserveModeEnabled() when service is foreground
│   ├── onPollingLoopDetected() receives polling frames
│   └── Broadcasts frames to MainActivity for display
│
├── MainActivity.java
│   ├── Uses CardEmulation.isObserveModeSupported() to check support
│   ├── Enables our HCE-F service to activate Observe Mode
│   ├── Registers BroadcastReceiver for polling frames
│   └── Displays frames in UI
│
└── NO XPOSED HOOKS NEEDED FOR OBSERVE MODE!
```

### How It Works

1. **Service Declaration** (`AndroidManifest.xml`):
   ```xml
   <service
       android:name=".nfc.HcefObserveModeService"
       android:permission="android.permission.BIND_NFC_SERVICE">
       <intent-filter>
           <action android:name="android.nfc.cardemulation.action.HOST_NFCF_SERVICE" />
       </intent-filter>
       <meta-data
           android:name="android.nfc.cardemulation.host_nfcf_service"
           android:resource="@xml/hcef_observe_mode_service" />
   </service>
   ```

2. **Service Configuration** (`res/xml/hcef_observe_mode_service.xml`):
   ```xml
   <host-nfcf-service>
       <polling-loop-filter android:name="nfcf" />
   </host-nfcf-service>
   ```

3. **Service Implementation** (`HcefObserveModeService.java`):
   ```java
   public class HcefObserveModeService extends HostNfcFService {
       @Override
       public void onPollingLoopDetected(List<PollingFrame> frames) {
           // THIS IS WHERE WE RECEIVE POLLING FRAMES!
           for (PollingFrame frame : frames) {
               int type = frame.getType();
               byte[] data = frame.getData();
               // Process SENSF_REQ with SC=FFFF here
           }
       }
   }
   ```

4. **System Behavior**:
   - When service becomes foreground, system calls `setObserveModeEnabled(true)`
   - NFCC enters Observe Mode: monitors RF but doesn't auto-respond
   - eSE is silenced - no automatic SENSF_RES
   - Polling frames delivered to `onPollingLoopDetected()`
   - When service goes background, system calls `setObserveModeEnabled(false)`

### API Usage

**WRONG (our original approach):**
```java
// Manual control via Xposed hooks - INCORRECT!
XposedHelpers.callMethod(nfcAdapter, "setObserveModeEnabled", true);
```

**CORRECT (Android 15 HCE API):**
```java
// Check support
CardEmulation cardEmulation = CardEmulation.getInstance(nfcAdapter);
boolean supported = cardEmulation.isObserveModeSupported();

// Enable service (system handles setObserveModeEnabled automatically)
ComponentName service = new ComponentName(context, HcefObserveModeService.class);
cardEmulation.setPreferredService(activity, service);
```

## Why Our Original Approach Was Wrong

### Mistake #1: Process Context
- **Wrong:** Running in `com.android.nfc` process via Xposed
- **Right:** Running in OUR app process as HostNfcFService

### Mistake #2: Manual API Calls
- **Wrong:** Manually calling `setObserveModeEnabled()` via reflection
- **Right:** System calls it automatically when service is foreground

### Mistake #3: No Service Declaration
- **Wrong:** No HostNfcFService implementation
- **Right:** Proper service extending HostNfcFService with polling-loop-filter

### Mistake #4: Wrong Callback
- **Wrong:** Hooking `onPollingLoopDetected()` in `com.android.nfc` process
- **Right:** Implementing `onPollingLoopDetected()` in OUR service

### Mistake #5: API Check
- **Wrong:** Checking `NfcAdapter.isObserveModeSupported()` (hidden API)
- **Right:** Using `CardEmulation.isObserveModeSupported()` (public API)

## References

- **android-observe-mode-demo**: https://github.com/kormax/android-observe-mode-demo
  - Complete working example of Observe Mode
  - Shows proper HostNfcFService implementation
  - Demonstrates polling-loop-filter usage

- **Android HCE Documentation**: https://developer.android.com/develop/connectivity/nfc/hce
  - Official Host Card Emulation guide
  - Explains service declaration and lifecycle

- **AOSP Source**:
  - `packages/apps/Nfc/src/com/android/nfc/HostEmulationManager.java`
  - Shows how system calls `setObserveModeEnabled()` automatically
  - Line ~380: `adapter.setObserveModeEnabled(true)` when service active

## Xposed Hooks - Still Needed for What?

Observe Mode activation is now handled by the system. Xposed hooks are ONLY needed for:

1. **Native layer bypass** (if needed for sending SENSF_RES):
   - Hook `nfa_dm_is_data_exchange_allowed()` to bypass state checks
   - This allows sending responses even though system doesn't expect it

2. **Debugging/Logging**:
   - Hook system NFC methods for analysis
   - Not required for basic Observe Mode functionality

## Summary

The key insight: **Observe Mode is a SYSTEM FEATURE, not something we implement**.

We don't "enable Observe Mode" - we create an HCE-F service with polling-loop-filters, and the SYSTEM enables Observe Mode for us when our service is active.

This is why the android-observe-mode-demo works perfectly with just a simple HostNfcFService - no Xposed, no reflection, no hacks. Just the official Android API.
