# AOSP NFC Stack - Observe Mode SENSF_RES Injection Analysis

**Target Version: Android 15** (Observe Mode was introduced in Android 15)

## 1. Executive Summary

This document provides technical analysis of the Android NFC stack (Android 15) for Host-based raw SENSF_RES injection in Observe Mode. The goal is to identify blocking factors and potential bypass methods.

**IMPORTANT**: Observe Mode is an Android 15 feature. Reference files have been updated to Android 15 (`android-15.0.0_r1`).

### Key Findings

1. **Primary Blocking Point**: `nfa_dm_act_send_raw_frame()` in libnfc-nci.so
   - Location: `nfa_dm_act.cc:1098-1137` (Android 15)
   - Condition: `disc_state != NFA_DM_RFST_POLL_ACTIVE && disc_state != NFA_DM_RFST_LISTEN_ACTIVE`
   - In Observe Mode, state remains `NFA_DM_RFST_DISCOVERY` (0x01), blocking TX

2. **Global Variables for State Manipulation**:
   - `nfa_dm_cb`: 0x24c0f8 (1160 bytes) - addresses from real device binary
   - `nfc_cb`: 0x24cf20 (680 bytes)
   - `disc_state` offset in `nfa_dm_cb.disc_cb`: varies by build

3. **Key Functions for Hooking**:
   - `NFA_SendRawFrame` @ 0x147100 (entry point)
   - `nfa_dm_act_send_raw_frame` @ 0x14e070 (state check)
   - `NFC_SendData` @ 0x183240 (lower level send)
   - `ce_t3t_send_to_lower` @ 0x18bdc0 (T3T specific)
   - `nfc_ncif_send_data` @ 0x184870 (NCI level)

4. **Observe Mode Implementation** (Android 15 specific):
   - NCI Proprietary Command: `NCI_ANDROID_PASSIVE_OBSERVE` (sub-opcode 0x2)
   - Query Command: `NCI_QUERY_ANDROID_PASSIVE_OBSERVE` (sub-opcode 0x4)
   - Polling Frame Notification: `NCI_ANDROID_POLLING_FRAME_NTF` (sub-opcode 0x3)
   - All under GID `0x0F` (NCI_GID_PROP) and OID `0x0C` (NCI_MSG_PROP_ANDROID)

---

## 2. NFA State Machine Analysis

### 2.1 Discovery States (from nfa_dm_int.h:230-238, Android 15)

```c
enum {
  NFA_DM_RFST_IDLE = 0,               // idle state
  NFA_DM_RFST_DISCOVERY = 1,          // discovery state (OBSERVE MODE)
  NFA_DM_RFST_W4_ALL_DISCOVERIES = 2, // wait for all discoveries
  NFA_DM_RFST_W4_HOST_SELECT = 3,     // wait for host selection
  NFA_DM_RFST_POLL_ACTIVE = 4,        // poll mode activated (TX ALLOWED)
  NFA_DM_RFST_LISTEN_ACTIVE = 5,      // listen mode activated (TX ALLOWED)
  NFA_DM_RFST_LISTEN_SLEEP = 6,       // listen mode sleep
  NFA_DM_RFST_LP_LISTEN = 7,          // Low Power listen
  NFA_DM_RFST_LP_ACTIVE = 8           // Low Power active
};
```

### 2.2 Blocking Logic in nfa_dm_act_send_raw_frame()

```c
// nfa_dm_act.cc:1098-1137 (Android 15)
bool nfa_dm_act_send_raw_frame(tNFA_DM_MSG* p_data) {
  tNFC_STATUS status = NFC_STATUS_FAILED;

  // CRITICAL: This is the blocking check
  if ((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_POLL_ACTIVE) ||
      (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE)) {
    
    // TX allowed - set flags and send
    nfa_dm_cb.flags |= NFA_DM_FLAGS_RAW_FRAME;
    NFC_SetReassemblyFlag(false);
    
    // Route to appropriate handler
    if (/* conditions for RW path */) {
      status = nfa_rw_send_raw_frame((NFC_HDR*)p_data);
    } else {
      status = NFC_SendData(NFC_RF_CONN_ID, (NFC_HDR*)p_data);
    }
  }
  
  // In Observe Mode (DISCOVERY state), this returns NFC_STATUS_FAILED
  return (status == NFC_STATUS_FAILED);
}
```

---

## 3. Symbol Table Reference (libnfc_nci_jni.so)

### 3.1 Primary Hooking Targets

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `NFA_SendRawFrame` | 0x147100 | 448 | API entry point |
| `nfa_dm_act_send_raw_frame` | 0x14e070 | 392 | State validation |
| `NFC_SendData` | 0x183240 | 104 | Lower level send |
| `nfc_ncif_send_data` | 0x184870 | 1196 | NCI frame construction |
| `ce_t3t_send_to_lower` | 0x18bdc0 | 400 | T3T specific path |

### 3.2 Global Variables

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `nfa_dm_cb` | 0x24c0f8 | 1160 | DM control block |
| `nfc_cb` | 0x24cf20 | 680 | NFC control block |

### 3.3 Observe Mode Functions

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `android_nfc_nfc_observe_mode` | 0x1f04f0 | 8 | JNI observe mode |
| `android_nfc_nfc_observe_mode_st_shim` | 0x1f0500 | 8 | ST shim |

### 3.4 State Machine Functions

| Symbol | Address | Size | Purpose |
|--------|---------|------|---------|
| `nfa_dm_disc_sm_execute` | 0x1516d0 | 5924 | State machine handler |
| `nfa_dm_act_start_rf_discovery` | 0x14e200 | 328 | Start discovery |
| `nfa_dm_act_stop_rf_discovery` | 0x14e350 | 380 | Stop discovery |
| `nfa_dm_act_deactivate` | 0x14d490 | 644 | Deactivate RF |

---

## 4. nfa_dm_cb Structure Layout

Based on `nfa_dm_int.h:524-580`, the `tNFA_DM_CB` structure:

```c
typedef struct {
  uint32_t flags;               // offset 0x00, NFA_DM flags
  tNFA_DM_CBACK* p_dm_cback;    // offset 0x04/0x08
  TIMER_LIST_ENT tle;           // timer entry
  tNFA_CONN_CBACK* p_conn_cback;
  tNFA_TECHNOLOGY_MASK poll_mask;
  // ... more fields ...
  tNFA_DM_DISC_CB disc_cb;      // Discovery control block
  // ... more fields ...
} tNFA_DM_CB;
```

The `tNFA_DM_DISC_CB` structure (offset ~0x50-0x100 in nfa_dm_cb):

```c
typedef struct {
  uint16_t disc_duration;           // offset 0x00
  tNFA_DM_DISC_FLAGS disc_flags;    // offset 0x02
  tNFA_DM_RF_DISC_STATE disc_state; // offset 0x04 (CRITICAL!)
  // ... more fields ...
} tNFA_DM_DISC_CB;
```

**Note**: Exact offsets may vary by build. Use runtime analysis with Frida to determine precise offsets.

---

## 5. Bypass Strategies

### 5.1 Strategy A: State Spoofing (Recommended)

**Approach**: Temporarily modify `nfa_dm_cb.disc_cb.disc_state` before calling send functions.

```javascript
// Frida pseudo-code
const nfa_dm_cb = Module.findExportByName("libnfc_nci_jni.so", "nfa_dm_cb");
const DISC_STATE_OFFSET = 0x04; // Verify at runtime
const NFA_DM_RFST_LISTEN_ACTIVE = 5;

function spoofState() {
    const statePtr = nfa_dm_cb.add(DISC_CB_OFFSET + DISC_STATE_OFFSET);
    const savedState = statePtr.readU8();
    statePtr.writeU8(NFA_DM_RFST_LISTEN_ACTIVE);
    return savedState;
}

function restoreState(savedState) {
    const statePtr = nfa_dm_cb.add(DISC_CB_OFFSET + DISC_STATE_OFFSET);
    statePtr.writeU8(savedState);
}
```

### 5.2 Strategy B: Function Hook (Alternative)

**Approach**: Hook `nfa_dm_act_send_raw_frame` and bypass the state check.

```javascript
// Frida hook on nfa_dm_act_send_raw_frame
Interceptor.attach(ptr("0x14e070"), {
    onEnter: function(args) {
        // Force state to LISTEN_ACTIVE before check
        spoofState();
        this.shouldRestore = true;
    },
    onLeave: function(retval) {
        if (this.shouldRestore) {
            restoreState();
        }
    }
});
```

### 5.3 Strategy C: Direct NFC_SendData Call

**Approach**: Bypass NFA layer entirely, call NFC_SendData directly.

**Risk**: May cause state inconsistencies.

```javascript
const NFC_SendData = new NativeFunction(
    Module.findExportByName("libnfc_nci_jni.so", "_Z12NFC_SendDatahP6tNFC_HDR"),
    'int', ['int', 'pointer']
);

// Build NFC_HDR structure and call directly
```

---

## 6. Timing Considerations

### 6.1 FeliCa Response Timing

- **Specification**: SENSF_RES must be sent within 2.4ms of SENSF_REQ
- **Reality**: Android userspace latency is typically 5-20ms
- **Mitigation**: Spray strategy - send multiple responses, rely on reader retry

### 6.2 Spray Strategy Parameters

Based on logcat analysis, reader typically retries 3-4 times with ~20ms intervals.

**Recommended spray parameters**:
- Spray count: 100 frames
- Interval: 3ms (matches task requirement)
- Total window: ~300ms

---

## 7. Logcat Analysis Reference

### 7.1 Normal HCE-F Response (non-wildcard)

Key events:
1. `NFA_DM_INTF_ACTIVATED_EVT` - Interface activated
2. `nfc_set_state; 4 (IDLE)->5 (OPEN)` - State transition
3. `nfa_dm_disc_new_state; LISTEN_ACTIVE (5)` - Discovery state change
4. `nfc_ncif_send_data` - Data transmission

### 7.2 Observe Mode (wildcard, no response)

Key events:
1. `NCI_ANDROID_POLLING_FRAME_NTF` - Polling frame notification
2. `onPollingLoopDetected()` - Host receives frame
3. **NO** state transition to LISTEN_ACTIVE
4. **NO** `nfc_ncif_send_data` calls

### 7.3 Difference Analysis

The critical difference: In Observe Mode, the discovery state remains `DISCOVERY (1)` 
instead of transitioning to `LISTEN_ACTIVE (5)`. This is by design - Observe Mode
prevents automatic response.

---

## 8. Recommended Hook Targets (Corrected)

Previous documentation contained incorrect function names. The correct targets are:

### Correct Native Targets

1. **`NFA_SendRawFrame`** (C++ mangled: `_Z16NFA_SendRawFramePhtt`)
   - Address: 0x147100
   - Signature: `tNFA_STATUS NFA_SendRawFrame(uint8_t*, uint16_t, uint16_t)`

2. **`nfa_dm_act_send_raw_frame`** (C++ mangled: `_Z25nfa_dm_act_send_raw_frameP12tNFA_DM_MSG`)
   - Address: 0x14e070
   - Signature: `bool nfa_dm_act_send_raw_frame(tNFA_DM_MSG*)`

3. **`NFC_SendData`** (C++ mangled: `_Z12NFC_SendDatahP6tNFC_HDR`)
   - Address: 0x183240
   - Signature: `tNFC_STATUS NFC_SendData(uint8_t, NFC_HDR*)`

4. **`ce_t3t_send_to_lower`** (C++ mangled: `_Z20ce_t3t_send_to_lowerP6tNFC_HDR`)
   - Address: 0x18bdc0
   - Signature: `tNFC_STATUS ce_t3t_send_to_lower(NFC_HDR*)`

### Incorrect Names (Do NOT Use)

The following function names do **NOT** exist in the binary:
- ~~`nfa_dm_is_data_exchange_allowed`~~ - Does not exist
- ~~`nfa_dm_send_raw_vs_frame`~~ - Incorrect name
- ~~`NFA_T3tSendRawFrame`~~ - Does not exist

---

## 9. Java/Xposed Hook Targets

For Java layer hooks (complementary to native hooks):

1. **`NfcService.sendData(byte[])`**
   - AOSP path: `packages/apps/Nfc/src/com/android/nfc/NfcService.java:4437`
   
2. **`NativeNfcManager.doSend(byte[])`**
   - JNI wrapper for native send

3. **`NativeNfcManager.doTransceive(byte[], boolean, int[])`**
   - Full transceive operation

---

## 10. Conclusion

### Answer to Question 1: Blocking Factor
The true blocking factor is the state check in `nfa_dm_act_send_raw_frame()` at the NFA layer.
This is a **software state machine constraint**, not a firmware/NCI limitation.

### Answer to Question 2: NCI-Level Bypass
Yes, there are bypass approaches:
1. State spoofing via `nfa_dm_cb.disc_cb.disc_state` modification
2. Function hook to bypass the state check
3. Direct `NFC_SendData` call (higher risk)

### Answer to Question 3: Implementation Approach
Use Frida to:
1. Hook `nfa_dm_act_send_raw_frame`
2. Temporarily spoof `disc_state` to `NFA_DM_RFST_LISTEN_ACTIVE (5)`
3. Allow TX to proceed
4. Restore original state

The 2.4ms timing constraint cannot be met in software, but the spray strategy
(100 frames @ 3ms intervals) provides probabilistic success through reader retry mechanisms.

---

## Appendix A: File References

Source files saved to `ref_aosp/`:
- `system_nfc/nfa_dm_act.cc` - Action functions (contains blocking logic)
- `system_nfc/nfa_dm_api.cc` - API entry points
- `system_nfc/nfa_dm_int.h` - Internal structures and constants
- `system_nfc/nci_hmsgs.cc` - NCI message construction
- `system_nfc/nci_defs.h` - NCI protocol definitions
- `packages_apps_Nfc/NfcService.java` - Java service
- `packages_apps_Nfc/HostEmulationManager.java` - HCE management
- `packages_apps_nfc/src/NfcObserveMode.java` - Observe Mode documentation

Binary files:
- `libnfc_nci_jni.so` - Real device NFC JNI library (for symbol analysis)
- `nfc_nci.st21nfc.st.so` - ST NFC HAL

---

*Document Version: 1.0*
*Analysis Date: 2024-12-29*
*Target: Android 14/15, libnfc-nci*
