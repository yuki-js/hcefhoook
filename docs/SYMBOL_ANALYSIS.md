# NFC Stack Symbol Analysis & Hook Targets

This document details the analysis of reference NFC libraries and identifies key hook targets for implementing SENSF_RES injection in Observe Mode.

## Analyzed Libraries

### 1. libnfc_nci_jni.so
- **Type**: ELF 64-bit LSB shared object, ARM aarch64
- **Build ID**: a21000b81842346daba9ab5eacb6243d
- **Purpose**: JNI bridge between Android Framework and native NFC stack
- **Status**: Stripped (no debugging symbols)

### 2. nfc_nci.st21nfc.st.so  
- **Type**: ELF 64-bit LSB shared object, ARM aarch64
- **Build ID**: f49b939ad8d38780ebbc1a5e60b9c2e7
- **Purpose**: STMicroelectronics ST21NFC chip-specific HAL implementation
- **Status**: Stripped (no debugging symbols)

## Key Hook Targets (Priority Order)

### CRITICAL: Main Data Send Path

#### 1. `nfa_dm_act_send_raw_frame(tNFA_DM_MSG*)`
- **Address (libnfc_nci_jni.so)**: `0x14e070`
- **Demangled Name**: `nfa_dm_act_send_raw_frame(tNFA_DM_MSG*)`
- **Purpose**: Main NFA layer function for sending raw frames
- **Hook Strategy**: 
  - This function checks discovery state before allowing transmission
  - In Observe Mode (DISCOVERY state), it blocks data sending
  - **Bypass Method**: Hook to skip state check or temporarily spoof state
- **Priority**: **HIGHEST** - This is the primary bottleneck

**Relevant AOSP Code** (from ref_aosp/system_nfc/...):
```cpp
bool nfa_dm_act_send_raw_frame(tNFA_DM_MSG* p_data) {
  tNFC_STATUS status = NFC_STATUS_FAILED;

  /* If NFC link is activated */
  if ((nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_POLL_ACTIVE) ||
      (nfa_dm_cb.disc_cb.disc_state == NFA_DM_RFST_LISTEN_ACTIVE)) {
    // Transmission allowed
    status = NFC_SendData(NFC_RF_CONN_ID, (NFC_HDR*)p_data);
  } else {
    // BLOCKED IN OBSERVE MODE (DISCOVERY STATE)
    return true;  // Free buffer, operation failed
  }
  return false;
}
```

#### 2. `NFC_SendData(unsigned char, NFC_HDR*)`
- **Address (libnfc_nci_jni.so)**: `0x183240`
- **Demangled Name**: `NFC_SendData(unsigned char, NFC_HDR*)`
- **Purpose**: Lower-level NCI data transmission function
- **Hook Strategy**:
  - Called after NFA state checks pass
  - Directly interfaces with NCI layer
  - **Spray Mode**: Monitor and allow continuous retransmission
- **Priority**: **HIGH** - Fallback if NFA-level bypass fails

### SUPPORTING: State Management

#### 3. `nfa_dm_is_data_exchange_allowed()` 
- **Symbol**: May not be exported (check via dlsym)
- **Purpose**: State validation function
- **Hook Strategy**:
  - Return `true` when bypass enabled
  - Allow data exchange in any state
- **Priority**: **MEDIUM** - May be inlined or static

#### 4. `nfa_dm_cb` Global Variable
- **Purpose**: NFA Discovery Manager control block
- **Contains**: `disc_cb.disc_state` (current discovery state)
- **Hook Strategy**:
  - Direct memory manipulation to spoof state
  - Temporarily set to `NFA_DM_RFST_LISTEN_ACTIVE` (0x05)
  - Restore original state after transmission
- **Priority**: **MEDIUM** - Alternative to function hooking

### OPTIONAL: Vendor-Specific Commands

#### 5. `nfa_dm_act_send_vsc(tNFA_DM_MSG*)`
- **Address (libnfc_nci_jni.so)**: `0x14d8e0`
- **Purpose**: Send vendor-specific commands
- **Hook Strategy**: Log and monitor for debugging
- **Priority**: **LOW**

#### 6. `nfa_dm_act_send_raw_vs(tNFA_DM_MSG*)`
- **Address (libnfc_nci_jni.so)**: `0x14d920`
- **Purpose**: Send raw vendor-specific data
- **Hook Strategy**: Log and monitor for debugging
- **Priority**: **LOW**

### HAL Layer (STMicroelectronics Specific)

#### 7. `HalSendDownstream(void*, unsigned char const*, unsigned long)`
- **Address (nfc_nci.st21nfc.st.so)**: `0x1bf20`
- **Purpose**: ST21NFC HAL layer downstream (to chip) transmission
- **Hook Strategy**:
  - Absolute last resort bypass
  - Directly sends data to I2C layer
  - **Warning**: May cause NCI protocol violations
- **Priority**: **VERY LOW** - Only if all upper layers fail

## Discovery States (NFA_DM_RFST_*)

From `nfa_dm_int.h`:

```c
#define NFA_DM_RFST_IDLE            0x00  // Idle - no RF activity
#define NFA_DM_RFST_DISCOVERY       0x01  // Discovery/Observe Mode (BLOCKS TX)
#define NFA_DM_RFST_W4_ALL_DISC     0x02  // Waiting for all discoveries
#define NFA_DM_RFST_W4_HOST_SELECT  0x03  // Waiting for host select
#define NFA_DM_RFST_POLL_ACTIVE     0x04  // Poll mode active (TX allowed)
#define NFA_DM_RFST_LISTEN_ACTIVE   0x05  // Listen mode active (TX allowed)
#define NFA_DM_RFST_LISTEN_SLEEP    0x06  // Listen sleep
```

**Key Insight**: In Observe Mode, state is `DISCOVERY` (0x01), which blocks transmission. Target state for bypass is `LISTEN_ACTIVE` (0x05).

## Hooking Implementation Strategy

### Phase 1: Java-Layer Xposed Hooks (Current Implementation)
- Hook NFC service Java methods
- Detect SENSF_REQ in Observe Mode
- Queue SENSF_RES for injection
- **Limitation**: Cannot bypass native state checks

### Phase 2: Native Function Hooking (Dobby - Future)
- Install inline hooks on `nfa_dm_act_send_raw_frame`
- Bypass state check when in bypass/spray mode
- Allow TX in DISCOVERY state
- **Requirement**: Dobby prebuilt library

### Phase 3: State Spoofing (Alternative)
- Locate `nfa_dm_cb` in memory
- Calculate offset of `disc_cb.disc_state`
- Temporarily write `NFA_DM_RFST_LISTEN_ACTIVE` before TX
- Restore original state after TX
- **Advantage**: No function hooking needed

### Phase 4: HAL Direct Access (Last Resort)
- Bypass entire NFA/NCI stack
- Direct HAL function calls
- **Warning**: May cause protocol violations, use only if necessary

## Observe Mode SENSF_REQ Flow

```
1. Reader sends SENSF_REQ (SC=FFFF)
   ↓
2. NFCC receives in Observe Mode (no auto-response)
   ↓
3. NFCC sends NCI_ANDROID_POLLING_FRAME_NTF to Host
   ↓
4. NFC Service receives notification (Java layer)
   ↓
5. Xposed hook detects SENSF_REQ (PollingFrameHook)
   ↓
6. Build SENSF_RES with custom IDm/PMm
   ↓
7. Call NFA_SendRawFrame() 
   ↓
8. nfa_dm_act_send_raw_frame() checks state
   ↓
9. **BLOCKED HERE** - state is DISCOVERY, not LISTEN_ACTIVE
   ↓
10. [HOOK/BYPASS NEEDED HERE]
   ↓
11. NFC_SendData() → NCI layer → NFCC → RF transmission
```

## Spray Strategy Implementation

For continuous SENSF_RES transmission to compensate for timing:

1. Enable spray mode flag in native hooks
2. On SENSF_REQ detection:
   - Send SENSF_RES immediately
   - Continue sending at ~1-2ms intervals
   - Stop after timeout (e.g., 20ms) or next polling frame
3. Probabilistic collision avoidance through continuous transmission
4. Increases likelihood of reader reception despite timing constraints

## Required Configuration Changes

### /vendor/etc/libnfc-nci.conf
```
# Enable Observe Mode
DISCOVER_MODE=0x01

# Enable NCI Android polling frame notifications  
NCI_ANDROID_POLLING_FRAME_NTF=0x01

# Disable eSE auto-response for SC=FFFF
ESE_LISTEN_TECH_MASK=0x00
```

### /vendor/etc/libnfc-nci-felica.conf (if exists)
```
# Allow Host-based FeliCa emulation
FELICA_HOST_LISTEN=0x01

# System Code for Host routing
FELICA_SYSTEM_CODE=0xFFFF
```

**Note**: These files require root/KernelSU for modification (Phase 3).

## Testing & Verification

1. **Symbol Resolution Test**: Verify dlsym can find target functions
2. **Hook Installation Test**: Confirm Dobby hooks install successfully  
3. **State Monitor Test**: Log discovery state transitions
4. **Bypass Test**: Enable bypass, attempt TX in DISCOVERY state
5. **Spray Test**: Verify continuous transmission works
6. **Real Reader Test**: Test against actual FeliCa reader/writer

## References

- AOSP system/nfc: `ref_aosp/system_nfc/`
- NCI Specification 2.2
- JIS X 6319-4 (FeliCa specification)
- Issue #1: https://github.com/yuki-js/hcefhoook/issues/1
