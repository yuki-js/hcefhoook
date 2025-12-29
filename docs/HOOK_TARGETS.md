# Hook Target Functions Reference

## Overview

This document provides a detailed reference of functions and memory addresses to hook for bypassing Observe Mode TX restrictions.

> **IMPORTANT UPDATE (2024-12-29)**: This document has been corrected based on actual binary analysis of `libnfc_nci_jni.so`. Several function names in previous versions were incorrect.

## 1. Primary Hook Targets

### ⚠️ CORRECTED: Function Names

**Previous documentation listed incorrect function names. The correct targets are:**

| Incorrect (Do NOT Use) | Correct |
|------------------------|---------|
| ~~`nfa_dm_is_data_exchange_allowed`~~ | Does not exist |
| ~~`nci_snd_data`~~ | `NFC_SendData` |
| ~~`_ZN3nfa2dm26is_data_exchange_allowedEv`~~ | Not found |

---

### 1.1 NFA_SendRawFrame() ✓ VERIFIED

**Purpose**: Public API for sending raw NFC frames

**Location**:
- Library: `libnfc_nci_jni.so` (or `libnfc-nci.so`)
- Source: `system/nfc/src/nfa/dm/nfa_dm_api.cc`

**Symbol Name (C++ mangled)**:
```
_Z16NFA_SendRawFramePhtt
```

**Address (libnfc_nci_jni.so)**: `0x147100`

**Signature**:
```cpp
tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, 
                              uint16_t data_len,
                              uint16_t presence_check_start_delay);
```

**Return Values**:
- `NFA_STATUS_OK (0x00)` - Success
- `NFA_STATUS_FAILED (0x01)` - Blocked by state

**Hook Strategy**:
```javascript
// Frida hook
const NFA_SendRawFrame = Module.findExportByName("libnfc_nci_jni.so", "_Z16NFA_SendRawFramePhtt");
Interceptor.attach(NFA_SendRawFrame, {
    onEnter: function(args) {
        this.data = args[0];
        this.len = args[1].toInt32();
        console.log("SendRawFrame: len=" + this.len);
    },
    onLeave: function(retval) {
        console.log("SendRawFrame result: " + retval);
    }
});
```

---

### 1.2 nfa_dm_act_send_raw_frame() ✓ VERIFIED - KEY BLOCKING POINT

**Purpose**: Internal action function with state validation

**Location**:
- Library: `libnfc_nci_jni.so`
- Source: `system/nfc/src/nfa/dm/nfa_dm_act.cc:1098`

**Symbol Name (C++ mangled)**:
```
_Z25nfa_dm_act_send_raw_frameP12tNFA_DM_MSG
```

**Address (libnfc_nci_jni.so)**: `0x14e070`

**Signature**:
```cpp
bool nfa_dm_act_send_raw_frame(tNFA_DM_MSG* p_data);
```

**Blocking Logic (nfa_dm_act.cc:1104-1105)**:
```cpp
// This is the ACTUAL state check that blocks TX in Observe Mode
if ((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_POLL_ACTIVE) ||
    (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE)) {
    // TX allowed
} else {
    // TX blocked - returns NFC_STATUS_FAILED
}
```

**Hook Strategy (State Spoofing)**:
```javascript
const nfa_dm_cb = Module.findExportByName("libnfc_nci_jni.so", "nfa_dm_cb");
const DISC_STATE_OFFSET = 0x04; // Verify at runtime!
const NFA_DM_RFST_LISTEN_ACTIVE = 5;

Interceptor.attach(ptr("0x14e070"), {
    onEnter: function(args) {
        // Spoof state before check
        const statePtr = nfa_dm_cb.add(DISC_STATE_OFFSET);
        this.savedState = statePtr.readU8();
        statePtr.writeU8(NFA_DM_RFST_LISTEN_ACTIVE);
    },
    onLeave: function(retval) {
        // Restore state
        const statePtr = nfa_dm_cb.add(DISC_STATE_OFFSET);
        statePtr.writeU8(this.savedState);
    }
});
```

---

### 1.3 NFC_SendData() ✓ VERIFIED

**Purpose**: Lower-level data send

**Location**:
- Library: `libnfc_nci_jni.so`
- Source: `system/nfc/src/nfc/nfc/nfc_main.cc`

**Symbol Name (C++ mangled)**:
```
_Z12NFC_SendDatahP7NFC_HDR
```

**Address (libnfc_nci_jni.so)**: `0x183240`

**Signature**:
```cpp
tNFC_STATUS NFC_SendData(uint8_t conn_id, NFC_HDR* p_buf);
```

**Key Parameters**:
- `conn_id`: `0x00` (NFC_RF_CONN_ID) for RF connection
- `p_buf`: NFC buffer structure

---

### 1.4 ce_t3t_send_to_lower() ✓ VERIFIED - T3T SPECIFIC

**Purpose**: Type 3 Tag (FeliCa) specific send function

**Location**:
- Library: `libnfc_nci_jni.so`
- Source: `system/nfc/src/nfc/tags/ce_t3t.cc`

**Symbol Name (C++ mangled)**:
```
_Z20ce_t3t_send_to_lowerP7NFC_HDR
```

**Address (libnfc_nci_jni.so)**: `0x18bdc0`

**Signature**:
```cpp
tNFC_STATUS ce_t3t_send_to_lower(NFC_HDR* p_buf);
```

---

### 1.5 nfc_ncif_send_data() ✓ VERIFIED

**Purpose**: NCI frame construction and send

**Address (libnfc_nci_jni.so)**: `0x184870`

**Symbol Name**:
```
_Z18nfc_ncif_send_dataP12tNFC_CONN_CBP7NFC_HDR
```

**Signature**:
```cpp
tNFC_STATUS nfc_ncif_send_data(tNFC_CONN_CB* p_cb, NFC_HDR* p_data);
```

---

## 2. Global Variable Targets

### 2.1 nfa_dm_cb ✓ VERIFIED

**Purpose**: Main NFA Device Manager control block

**Symbol**: `nfa_dm_cb`
**Address (libnfc_nci_jni.so)**: `0x24c0f8`
**Size**: 1160 bytes

**Structure (tNFA_DM_CB from nfa_dm_int.h)**:
```cpp
typedef struct {
    uint32_t flags;                    // offset 0x00
    tNFA_DM_CBACK* p_dm_cback;         // offset 0x04/0x08
    TIMER_LIST_ENT tle;                // timer entry
    tNFA_CONN_CBACK* p_conn_cback;
    tNFA_TECHNOLOGY_MASK poll_mask;
    // ... more fields ...
    tNFA_DM_DISC_CB disc_cb;           // Discovery control block
    // ... more fields ...
} tNFA_DM_CB;
```

**Discovery Control Block (tNFA_DM_DISC_CB)**:
```cpp
typedef struct {
    uint16_t disc_duration;                    // offset 0x00
    tNFA_DM_DISC_FLAGS disc_flags;             // offset 0x02
    tNFA_DM_RF_DISC_STATE disc_state;          // offset 0x04 ★KEY
    tNFC_RF_TECH_N_MODE activated_tech_mode;   // offset 0x05
    // ... more fields ...
} tNFA_DM_DISC_CB;
```

**Discovery State Values**:
```cpp
enum {
    NFA_DM_RFST_IDLE              = 0,  // idle state
    NFA_DM_RFST_DISCOVERY         = 1,  // ← Current in Observe Mode
    NFA_DM_RFST_W4_ALL_DISCOVERIES= 2,
    NFA_DM_RFST_W4_HOST_SELECT    = 3,
    NFA_DM_RFST_POLL_ACTIVE       = 4,  // TX allowed
    NFA_DM_RFST_LISTEN_ACTIVE     = 5,  // ← Required for TX
    NFA_DM_RFST_LISTEN_SLEEP      = 6,
    NFA_DM_RFST_LP_LISTEN         = 7,
    NFA_DM_RFST_LP_ACTIVE         = 8
};
```

**Runtime Offset Detection**:
```javascript
// Find disc_cb offset in nfa_dm_cb at runtime
function findDiscStateOffset() {
    const nfa_dm_cb = Module.findExportByName("libnfc_nci_jni.so", "nfa_dm_cb");
    
    // Search for disc_state value (usually 0x00-0x08)
    for (let offset = 0; offset < 0x100; offset++) {
        const val = nfa_dm_cb.add(offset).readU8();
        // Look for known state patterns
        if (val >= 0 && val <= 8) {
            console.log("Potential disc_state at offset 0x" + offset.toString(16) + ": " + val);
        }
    }
}
```

---

### 2.2 nfc_cb ✓ VERIFIED

**Purpose**: Lower-level NFC control block

**Symbol**: `nfc_cb`
**Address (libnfc_nci_jni.so)**: `0x24cf20`
**Size**: 680 bytes

---

## 3. Observe Mode Functions ✓ VERIFIED

### 3.1 android_nfc_nfc_observe_mode

**Address (libnfc_nci_jni.so)**: `0x1f04f0`
**Size**: 8 bytes

### 3.2 android_nfc_nfc_observe_mode_st_shim

**Address (libnfc_nci_jni.so)**: `0x1f0500`
**Size**: 8 bytes (ST chipset shim)

---

## 4. Symbol Discovery Methods

### 4.1 Using readelf (Recommended)

```bash
# Extract symbols from device
adb pull /system_ext/lib64/libstnfc_nci_jni.so

# List all symbols with demangled names
readelf --dyn-syms -W libstnfc_nci_jni.so | c++filt | grep -E "NFA_Send|nfa_dm|NFC_Send|ce_t3t"
```

### 4.2 Using Frida

```javascript
// Find specific function
const target = Module.findExportByName("libnfc_nci_jni.so", "_Z16NFA_SendRawFramePhtt");
console.log("NFA_SendRawFrame at: " + target);

// Enumerate all NFA-related symbols
Module.enumerateSymbols("libnfc_nci_jni.so").forEach(function(sym) {
    if (sym.name.match(/nfa_dm|NFA_Send|NFC_Send/i)) {
        console.log(sym.name + " @ " + sym.address);
    }
});
```

---

## 5. Complete Bypass Flow (Corrected)

```
1. Attach to com.android.nfc process
2. Find libnfc_nci_jni.so (or libstnfc_nci_jni.so) base address
3. Locate nfa_dm_cb global variable @ 0x24c0f8
4. Determine disc_state offset within disc_cb (~0x04 from disc_cb start)
5. On SENSF_REQ detection in Observe Mode:
   a. Read current disc_state value
   b. Temporarily write NFA_DM_RFST_LISTEN_ACTIVE (5) to disc_state
   c. Build SENSF_RES packet (18 bytes: [len][0x01][IDm 8B][PMm 8B])
   d. Call NFA_SendRawFrame() or hook nfa_dm_act_send_raw_frame()
   e. Immediately restore original disc_state
6. For Spray Mode: Repeat steps 5a-5e for 100 iterations with 3ms intervals
```

---

## 6. Hooking Framework Recommendations

### 6.1 Frida (Recommended)

**Pros**:
- Rapid development and testing
- No compilation required
- Can be injected remotely via frida-server
- RPC interface for integration with Java/Kotlin

**Usage**:
```bash
# Inject script into NFC process
frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause
```

### 6.2 Xposed/LSPosed (For Java Layer)

**Use Cases**:
- Hook `NfcService.sendRawFrame()`
- Monitor `HostEmulationManager.onPollingLoopDetected()`
- State coordination

### 6.3 Native Hooking (Dobby removed)

**Note**: Dobby-based hooks have been removed due to reliability issues.
Use Frida for all native hooking requirements.

---

*Reference Document Version: 2.0 (Corrected)*
*Target: Android 15+ (Observe Mode introduced in Android 15)*
*Last Updated: 2024-12-29*
