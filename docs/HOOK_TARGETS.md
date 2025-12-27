# Hook Target Functions Reference

## Overview

This document provides a detailed reference of functions and memory addresses to hook for bypassing Observe Mode TX restrictions.

## 1. Primary Hook Targets

### 1.1 nfa_dm_is_data_exchange_allowed()

**Purpose**: State validation gate for data exchange operations

**Location**:
- Library: `libnfc-nci.so`
- Source: `system/nfc/src/nfa/dm/nfa_dm_discover.cc`

**Symbol Names** (may vary by build):
```
C++ mangled:   _ZN3nfa2dm26is_data_exchange_allowedEv
Alternative:   _Z30nfa_dm_is_data_exchange_allowedv
Demangled:     nfa::dm::is_data_exchange_allowed()
```

**Signature**:
```cpp
bool nfa_dm_is_data_exchange_allowed(void);
```

**Hook Strategy**:
```javascript
// Frida hook - force return true
Interceptor.replace(target, new NativeCallback(function() {
    return 1; // true
}, 'bool', []));
```

**Dobby Hook (C++)**:
```cpp
bool (*orig_is_data_exchange_allowed)(void);
bool hooked_is_data_exchange_allowed(void) {
    return true; // Bypass state check
}
// DobbyHook(target_addr, (void*)hooked_is_data_exchange_allowed, (void**)&orig_is_data_exchange_allowed);
```

---

### 1.2 NFA_SendRawFrame()

**Purpose**: Public API for sending raw NFC frames

**Location**:
- Library: `libnfc-nci.so`
- Source: `system/nfc/src/nfa/dm/nfa_dm_api.cc`

**Symbol Name**:
```
NFA_SendRawFrame (C linkage, not mangled)
```

**Signature**:
```cpp
tNFA_STATUS NFA_SendRawFrame(uint8_t* p_raw_data, 
                              uint16_t data_len,
                              uint16_t presence_check_start_delay);
```

**Return Values**:
- `NFA_STATUS_OK (0x00)` - Success
- `NFA_STATUS_WRONG_DISCOVERY_STATE (0x0A)` - Blocked by state

**Hook Strategy**:
```javascript
// Monitor and potentially bypass state check inside
Interceptor.attach(target, {
    onEnter: function(args) {
        this.data = args[0];
        this.len = args[1].toInt32();
        console.log("SendRawFrame: " + hexdump(this.data, {length: this.len}));
    },
    onLeave: function(retval) {
        if (retval.toInt32() === 0x0A) {
            console.log("Blocked by state - attempting bypass...");
            // Alternative: call internal function directly
        }
    }
});
```

---

### 1.3 nci_snd_data()

**Purpose**: NCI layer data transmission

**Location**:
- Library: `libnfc-nci.so`
- Source: `system/nfc/src/nfc/nci/nci_hmsgs.cc`

**Symbol Names**:
```
C++ mangled:   _Z12nci_snd_datahP6BT_HDR
Alternative:   _ZN3nci8snd_dataEhP6BT_HDR
```

**Signature**:
```cpp
tNCI_STATUS nci_snd_data(uint8_t conn_id, BT_HDR* p_buf);
```

**Key Parameters**:
- `conn_id`: 0x00 for static RF connection
- `p_buf`: NFC buffer structure

**BT_HDR Structure**:
```cpp
typedef struct {
    uint16_t event;     // Event type
    uint16_t len;       // Data length
    uint16_t offset;    // Offset to data
    uint16_t layer_specific;
    // Followed by data bytes
} BT_HDR;
```

**Hook Strategy**:
```javascript
// Bypass connection ID validation
Interceptor.attach(target, {
    onEnter: function(args) {
        // Force conn_id to static RF connection
        args[0] = ptr(0x00);
    }
});
```

---

### 1.4 nfc_ncif_send_data()

**Purpose**: Lower-level data send to HAL

**Location**:
- Library: `libnfc-nci.so`
- Source: `system/nfc/src/nfc/nci/nci_hmsgs.cc`

**Symbol Names**:
```
C++ mangled:   _ZN3nfc5ncif9send_dataEP6BT_HDRh
Alternative:   _Z18nfc_ncif_send_dataP6BT_HDRh
```

**Signature**:
```cpp
void nfc_ncif_send_data(BT_HDR* p_buf, uint8_t conn_id);
```

**Hook Usage**: Direct call to bypass upper-level checks

---

## 2. Global Variable Targets

### 2.1 nfa_dm_cb

**Purpose**: Main NFA Device Manager control block

**Structure Offset Map**:
```
Offset  Field                      Type      Description
------  -------------------------  --------  ----------------------
0x00    flags                      uint32_t  DM flags
0x04    disc_cb                    struct    Discovery control block
  +0x00   disc_cb.disc_state       uint8_t   Discovery state ★KEY
  +0x01   disc_cb.disc_flags       uint8_t   Discovery flags
  +0x02   disc_cb.listen_tech_mask uint16_t  Listen technologies
  ...
```

**Discovery State Values**:
```cpp
#define NFA_DM_RFST_IDLE              0x00
#define NFA_DM_RFST_DISCOVERY         0x01  // ← Current in Observe Mode
#define NFA_DM_RFST_W4_ALL_DISC       0x02
#define NFA_DM_RFST_W4_HOST_SELECT    0x03
#define NFA_DM_RFST_POLL_ACTIVE       0x04
#define NFA_DM_RFST_LISTEN_ACTIVE     0x05  // ← Required for TX
#define NFA_DM_RFST_LISTEN_SLEEP      0x06
```

**Finding the Symbol**:
```javascript
// Method 1: Symbol lookup
const nfa_dm_cb = Module.findExportByName("libnfc-nci.so", "nfa_dm_cb");

// Method 2: Pattern scanning (if symbol stripped)
const pattern = "01 00 00 00";  // disc_state = DISCOVERY
Memory.scanSync(base, size, pattern);
```

**Modification**:
```javascript
// Temporarily spoof state
const discStatePtr = nfa_dm_cb.add(0x04);  // offset to disc_state
const original = discStatePtr.readU8();
discStatePtr.writeU8(0x05);  // LISTEN_ACTIVE
// ... perform TX ...
discStatePtr.writeU8(original);  // Restore
```

---

### 2.2 nfc_cb

**Purpose**: Lower-level NFC control block

**Structure Offset Map**:
```
Offset  Field           Type      Description
------  --------------  --------  ----------------------
0x00    nfc_state       uint8_t   NFC subsystem state
0x01    num_conn_cbs    uint8_t   Number of connections
0x04    conn_cb[0]      struct    Connection control block
  +0x00   p_cback       pointer   Callback function
  +0x08   conn_id       uint8_t   Connection ID
  ...
```

**NFC State Values**:
```cpp
#define NFC_STATE_NONE              0x00
#define NFC_STATE_W4_HAL_OPEN       0x01
#define NFC_STATE_CORE_INIT         0x02
#define NFC_STATE_W4_POST_INIT      0x03
#define NFC_STATE_IDLE              0x04
#define NFC_STATE_OPEN              0x05  // ← Required for TX
#define NFC_STATE_CLOSING           0x06
```

---

### 2.3 nfc_hal_entry

**Purpose**: HAL function table pointer

**Structure**:
```cpp
typedef struct {
    void (*open)(callback1, callback2);
    void (*close)(void);
    void (*core_initialized)(uint16_t, uint8_t*);
    int (*write)(uint16_t, uint8_t*);  // ★ Direct TX
    int (*prediscover)(void);
    void (*control_granted)(void);
    void (*power_cycle)(void);
    int (*get_max_nfcee)(void);
} tHAL_NFC_ENTRY;
```

**Direct HAL Write**:
```javascript
// Find HAL entry
const nfc_hal_entry = Module.findExportByName("libnfc-nci.so", "nfc_hal_entry");
const hal_table = nfc_hal_entry.readPointer();
const hal_write = hal_table.add(3 * Process.pointerSize).readPointer();

// Create NativeFunction
const halWrite = new NativeFunction(hal_write, 'int', ['uint16', 'pointer']);

// Send raw NCI packet
const packet = Memory.alloc(32);
// ... build packet ...
halWrite(packet_len, packet);
```

---

## 3. Symbol Discovery Methods

### 3.1 Using nm/objdump

```bash
# Extract symbols
adb pull /system/lib64/libnfc-nci.so
nm -C libnfc-nci.so | grep -E "nfa_dm|nci_snd|SendRaw"

# Look for specific patterns
objdump -t libnfc-nci.so | grep -i "data_exchange"
```

### 3.2 Using Frida

```javascript
// Enumerate all exports
Module.enumerateExports("libnfc-nci.so").forEach(function(exp) {
    if (exp.name.match(/nfa|nci|send|data/i)) {
        console.log(exp.type + ": " + exp.name + " @ " + exp.address);
    }
});

// Enumerate all symbols (including internal)
Module.enumerateSymbols("libnfc-nci.so").forEach(function(sym) {
    if (sym.name.match(/dm_cb|nfc_cb|hal_entry/i)) {
        console.log(sym.name + " @ " + sym.address);
    }
});
```

### 3.3 Pattern Matching (for stripped binaries)

```javascript
// Search for function prologue patterns
const patterns = [
    // ARM64 function prologue
    "FD 7B BF A9",  // stp x29, x30, [sp, #-0x10]!
    // Followed by specific instruction patterns
];

// Search for string references
const strRef = Memory.scanSync(base, size, 
    Array.from("is_data_exchange").map(c => c.charCodeAt(0).toString(16)).join(" "));
```

---

## 4. Hooking Framework Recommendations

### 4.1 Frida (Recommended for Development)

**Pros**:
- Easy to use, rapid iteration
- No need to recompile
- Excellent debugging support

**Cons**:
- Requires PC connection or frida-server
- May be detected by anti-tampering

### 4.2 Xposed/LSPosed (For Java Layer)

**Use Case**: Hook NfcService.java methods

**Pros**:
- Persistent hooks
- No root required (with LSPosed)

**Cons**:
- Java layer only
- Need to reboot for changes

### 4.3 Dobby/Substrate (For Production)

**Pros**:
- Native library injection
- No frida-server required
- More stealthy

**Cons**:
- Requires compilation
- More complex setup

---

## 5. Example: Complete Bypass Flow

```
1. Attach to com.android.nfc process
2. Find libnfc-nci.so base address
3. Locate nfa_dm_cb global variable
4. Hook nfa_dm_is_data_exchange_allowed() → return true
5. On SENSF_REQ detection:
   a. Read current disc_state
   b. Write LISTEN_ACTIVE (0x05) to disc_state
   c. Build SENSF_RES packet
   d. Call NFA_SendRawFrame() or direct HAL write
   e. Restore original disc_state
6. Monitor result
```

---

*Reference Document Version: 1.0*
*Target: Android 14/15, libnfc-nci.so*
