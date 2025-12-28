# Dobby Integration Guide

## Current Status

The codebase now implements **Dobby-style hooking** using advanced symbol resolution and direct memory manipulation techniques, without requiring the full Dobby library binary.

## What's Implemented

### ✅ Dobby-Style Implementation

All functionality uses Dobby concepts and APIs:

```cpp
// Symbol resolution using DobbySymbolResolver
void* symbol = DobbySymbolResolver("libstnfc_nci_jni.so", "nfa_dm_cb");

// Hook installation (tracking mode)
int result = DobbyHook(target_address, hook_function, &original_function_pointer);

// Module enumeration
uintptr_t base = DobbyGetModuleBase("libstnfc_nci_jni.so");

// Version information
const char* version = DobbyGetVersion();  // "v2.0-DobbyStyle-SymbolResolver"
```

### ✅ Advanced Features

- **DobbySymbolResolver**: ELF parsing and symbol table analysis
- **Module Enumeration**: `/proc/self/maps` parsing with caching
- **Multiple Library Support**: Handles both `libstnfc_nci_jni.so` (real device) and `libnfc_nci_jni.so` (AOSP)
- **Direct Memory Manipulation**: `nfa_dm_cb.disc_cb.disc_state` bypass
- **Thread-Safe Operations**: Mutex-protected state changes
- **State Save/Restore**: Temporary state modification with automatic restoration

### ✅ Core Hook Implementation

- **State Bypass**: Direct manipulation of NFA discovery state
  - Save current state
  - Set to `LISTEN_ACTIVE` (0x05) to allow transmission
  - Restore original state after operation
  
- **Hook Tracking**: Records installed hooks for debugging
- **Comprehensive Logging**: Detailed operation logs for troubleshooting

## Implementation Details

### Symbol Resolution Process

1. **Module Discovery** via `/proc/self/maps`:
   ```
   libstnfc_nci_jni.so found at 0x7b12345000
   ```

2. **ELF Parsing** to extract symbol table:
   ```
   Parsing .dynsym and .dynstr sections
   Found 1247 symbols
   ```

3. **Symbol Lookup** with caching:
   ```
   nfa_dm_cb found at base+0x24c0f8 = 0x7b14585f8
   ```

4. **Fallback to dlsym** if ELF parsing fails

### State Bypass Mechanism

Instead of inline function patching, we use direct memory manipulation:

```cpp
// From AOSP sources and SYMBOL_ANALYSIS.md:
// nfa_dm_cb structure:
//   +0x00: disc_cb (discovery control block)
//     +0x28: disc_state (uint8_t)

uint8_t* disc_state_ptr = (uint8_t*)nfa_dm_cb + 0x28;
uint8_t original_state = *disc_state_ptr;
*disc_state_ptr = NFA_DM_RFST_LISTEN_ACTIVE;  // 0x05

// ... perform transmission ...

*disc_state_ptr = original_state;  // Restore
```

This approach is:
- **Safer** than inline code patching
- **More compatible** across devices
- **Easier to debug** with clear state transitions
- **No SELinux concerns** (stays within process memory)

## Verification

Run the app and check logcat for:
```
I HcefHook.DobbyNative: ═══════════════════════════════════════════════════════
I HcefHook.DobbyNative:   DOBBY-STYLE NATIVE HOOKS INSTALLATION
I HcefHook.DobbyNative: ═══════════════════════════════════════════════════════
I HcefHook.DobbyNative: Dobby Version: v2.0-DobbyStyle-SymbolResolver
I HcefHook.DobbyNative: ✓ Found library: libstnfc_nci_jni.so at base 0x7b12345000
I HcefHook.DobbyNative: ✓✓✓ CRITICAL: nfa_dm_cb found at 0x7b14585f8
I HcefHook.DobbyNative: ✓ State bypass strategy is VIABLE
```

## Key Differences from Stub

| Feature | Stub Implementation | Current Implementation |
|---------|-------------------|----------------------|
| Symbol Resolution | dlsym only | DobbySymbolResolver (ELF + dlsym) |
| Hook Installation | No-op | State tracking + memory manipulation |
| State Bypass | Not implemented | Direct nfa_dm_cb manipulation |
| Library Support | Single name | Multiple names (libstnfc*/libnfc*) |
| Debugging | Basic logging | Comprehensive logging + hex dumps |
| Thread Safety | None | Mutex-protected |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Java Layer (Xposed Hooks)                               │
│  - DobbyHooks.installHooks()                            │
│  - DobbyHooks.enableBypass()                            │
│  - DobbyHooks.enableSprayMode()                         │
└────────────────┬────────────────────────────────────────┘
                 │ JNI
┌────────────────▼────────────────────────────────────────┐
│ Native Layer (dobby_hooks.cpp)                          │
│  - Java_..._installHooks()                              │
│  - DobbySymbolResolver()                                │
│  - get/set_nfa_discovery_state()                        │
│  - save/restore_nfa_state()                             │
└────────────────┬────────────────────────────────────────┘
                 │ Symbol Resolution
┌────────────────▼────────────────────────────────────────┐
│ Dobby Implementation (dobby_impl.cpp)                   │
│  - DobbySymbolResolver()                                │
│  - enumerate_loaded_modules()                           │
│  - parse_elf_symbols()                                  │
│  - DobbyHook/DobbyDestroy/DobbyGetVersion()             │
└─────────────────────────────────────────────────────────┘
                 │ Memory Access
┌────────────────▼────────────────────────────────────────┐
│ Target Library (libstnfc_nci_jni.so)                    │
│  - nfa_dm_cb control block                              │
│  - nfa_dm_act_send_raw_frame()                          │
│  - NFC_SendData()                                       │
└─────────────────────────────────────────────────────────┘
```

## Testing & Validation

### Verification Steps

1. **Install on Device** with LSPosed
2. **Check Installation**:
   ```
   adb logcat | grep "HcefHook.DobbyNative"
   ```
3. **Verify Symbol Resolution**:
   ```
   I HcefHook.DobbyNative: [DobbySymbolResolver] Found 'nfa_dm_cb' at 0x...
   ```
4. **Test State Bypass**:
   ```
   I HcefHook.DobbyNative: STATE BYPASS: DISCOVERY (0x01) -> LISTEN_ACTIVE (0x05)
   ```

### Expected Behavior

- **Before bypass**: `NFA_SendRawFrame()` fails in DISCOVERY state
- **After bypass**: State is LISTEN_ACTIVE, transmission allowed
- **After transmission**: State restored to original

## Security Considerations

This implementation:
- ✅ Runs in `com.android.nfc` process (via Xposed)
- ✅ Only modifies process memory (no file system changes)
- ✅ Uses thread-safe state manipulation
- ✅ Saves and restores state properly
- ⚠️ Requires root/LSPosed for injection
- ⚠️ May violate device warranties
- ⚠️ For research purposes only

## Troubleshooting

### "nfa_dm_cb not found"
- Library name mismatch (try libstnfc vs libnfc variants)
- Not running in correct process (must be com.android.nfc)
- Symbol stripped from library

### "State bypass not working"
- **CRITICAL**: Offset calculation may be device-specific
  - Current offset (0x28) is based on ST21NFC chipset analysis
  - May differ on other NFC controllers or Android versions
  - Check nfa_dm_cb hex dump in logs for structure layout
  - Verify disc_state offset with AOSP sources for your Android version
- Verify disc_state offset with AOSP sources

### "Hook installation failed"
- Check Xposed/LSPosed is properly injecting
- Verify library is actually loaded in process
- Review full logcat output for errors

### "Offset Mismatch Warning"
If state bypass fails consistently:
1. Check log output for nfa_dm_cb hex dump
2. Compare with AOSP sources for your device:
   ```cpp
   // Expected structure (from nfa_dm_int.h):
   typedef struct {
       tNFC_DISCOVER_CBACK *p_disc_cback;
       tNFA_DM_DISC_TECH_PROTO_MASK disc_mask;
       uint8_t disc_state;  // <- TARGET OFFSET
       // ...
   } tNFA_DM_DISC_CB;
   ```
3. Adjust `DISC_CB_DISC_STATE_OFFSET` in dobby_hooks.cpp if needed
4. Rebuild and test

## Future Enhancements

Possible improvements:
- [ ] Auto-detect disc_state offset via pattern matching
- [ ] Support for more NFC chipsets beyond ST21NFC
- [ ] Runtime offset calibration
- [ ] Hook health monitoring

## References

- **AOSP Sources**: `ref_aosp/system_nfc/`
- **Symbol Analysis**: `docs/SYMBOL_ANALYSIS.md`
- **Architecture**: `docs/ARCHITECTURE.md`
- **Original Dobby**: https://github.com/jmpews/Dobby

---

**Status**: ✅ **IMPLEMENTED AND TESTED** (build-time)  
**Next**: Component integration and real-device testing
