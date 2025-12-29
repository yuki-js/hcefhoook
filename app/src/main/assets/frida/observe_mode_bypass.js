/**
 * HCE-F Hook - Frida Script for Observe Mode SENSF_RES Injection
 * 
 * This script bypasses the NFA state machine to allow raw frame transmission
 * in Observe Mode (Discovery state).
 * 
 * Based on AOSP analysis documented in ref_aosp/AOSP_NFC_ANALYSIS.md
 * 
 * Target: Android 15+ (Observe Mode was introduced in Android 15)
 * Libraries: libstnfc_nci_jni.so (ST devices) or libnfc_nci_jni.so (AOSP)
 * 
 * Key Symbols (from binary analysis):
 *   - NFA_SendRawFrame @ 0x147100 (mangled: _Z16NFA_SendRawFramePhtt)
 *   - nfa_dm_act_send_raw_frame @ 0x14e070
 *   - NFC_SendData @ 0x183240
 *   - nfa_dm_cb @ 0x24c0f8 (1160 bytes)
 *   - nfc_cb @ 0x24cf20 (680 bytes)
 * 
 * Usage:
 *   frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause
 *   or inject via frida-server
 * 
 * RPC Interface:
 *   - sendSensfRes(idmHex, pmmHex) - Send single SENSF_RES
 *   - spraySensfRes(idmHex, pmmHex, count, intervalMs) - Spray mode
 *   - enableBypass() / disableBypass() - State bypass control
 *   - getState() - Get current discovery state
 *   - getInfo() - Get module and symbol information
 */

'use strict';

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
    // Library names to search (ordered by priority)
    libraryNames: [
        'libstnfc_nci_jni.so',    // ST NFC chipset (Pixel devices)
        'libnfc_nci_jni.so',      // Standard AOSP
        'libnfc-nci.so'           // Alternative naming
    ],
    
    // NFA Discovery States (from nfa_dm_int.h:230-238, Android 15)
    NFA_DM_RFST_IDLE: 0x00,
    NFA_DM_RFST_DISCOVERY: 0x01,          // Observe Mode state
    NFA_DM_RFST_W4_ALL_DISCOVERIES: 0x02,
    NFA_DM_RFST_W4_HOST_SELECT: 0x03,
    NFA_DM_RFST_POLL_ACTIVE: 0x04,
    NFA_DM_RFST_LISTEN_ACTIVE: 0x05,      // Required for TX
    NFA_DM_RFST_LISTEN_SLEEP: 0x06,
    NFA_DM_RFST_LP_LISTEN: 0x07,
    NFA_DM_RFST_LP_ACTIVE: 0x08,
    
    // Known symbol addresses (from libnfc_nci_jni.so analysis)
    // These are offsets from module base
    symbols: {
        NFA_SendRawFrame: {
            mangled: '_Z16NFA_SendRawFramePhtt',
            offset: 0x147100
        },
        nfa_dm_act_send_raw_frame: {
            mangled: '_Z25nfa_dm_act_send_raw_frameP12tNFA_DM_MSG',
            offset: 0x14e070
        },
        NFC_SendData: {
            mangled: '_Z12NFC_SendDatahP7NFC_HDR',
            offset: 0x183240
        },
        nfa_dm_cb: {
            offset: 0x24c0f8,
            size: 1160
        },
        nfc_cb: {
            offset: 0x24cf20,
            size: 680
        }
    },
    
    // Structure offsets (verify at runtime!)
    // disc_state is within disc_cb structure in nfa_dm_cb
    // Based on tNFA_DM_CB and tNFA_DM_DISC_CB structures
    DISC_CB_OFFSET_IN_DM_CB: 0x50,  // Approximate - verify at runtime
    DISC_STATE_OFFSET_IN_DISC_CB: 0x04,
    
    // Logging
    verbose: true,
    
    // Spray defaults
    defaultSprayCount: 100,
    defaultSprayIntervalMs: 3
};

// ============================================================================
// Logging Utilities
// ============================================================================

function log(msg) {
    console.log('[HcefHook] ' + msg);
}

function logv(msg) {
    if (CONFIG.verbose) {
        console.log('[HcefHook.v] ' + msg);
    }
}

function logError(msg) {
    console.log('[HcefHook.ERROR] ' + msg);
}

function hexdump_short(ptr, len) {
    if (!ptr || ptr.isNull() || len <= 0) return '(null)';
    try {
        let result = '';
        for (let i = 0; i < Math.min(len, 32); i++) {
            result += ('0' + (ptr.add(i).readU8() & 0xFF).toString(16)).slice(-2) + ' ';
        }
        if (len > 32) result += '...';
        return result.trim();
    } catch (e) {
        return '(read error)';
    }
}

// ============================================================================
// Module Discovery
// ============================================================================

let nfcModule = null;
let nfcModuleName = null;

function findNfcModule() {
    if (nfcModule) return nfcModule;
    
    for (const libName of CONFIG.libraryNames) {
        try {
            const mod = Process.findModuleByName(libName);
            if (mod) {
                nfcModule = mod;
                nfcModuleName = libName;
                log('✓ Found NFC library: ' + libName);
                log('  Base: ' + mod.base);
                log('  Size: ' + mod.size + ' bytes');
                return mod;
            }
        } catch (e) {
            // Module not found, continue
        }
    }
    
    logError('No NFC library found! Tried: ' + CONFIG.libraryNames.join(', '));
    return null;
}

// ============================================================================
// Symbol Resolution
// ============================================================================

const resolvedSymbols = {};

function resolveSymbol(name) {
    if (resolvedSymbols[name]) return resolvedSymbols[name];
    
    const mod = findNfcModule();
    if (!mod) return null;
    
    // Check if we have predefined offset
    if (CONFIG.symbols[name] && CONFIG.symbols[name].offset) {
        const addr = mod.base.add(CONFIG.symbols[name].offset);
        resolvedSymbols[name] = addr;
        logv('Symbol (offset): ' + name + ' @ ' + addr);
        return addr;
    }
    
    // Try mangled name if available
    if (CONFIG.symbols[name] && CONFIG.symbols[name].mangled) {
        let addr = Module.findExportByName(nfcModuleName, CONFIG.symbols[name].mangled);
        if (addr) {
            resolvedSymbols[name] = addr;
            logv('Symbol (export): ' + name + ' @ ' + addr);
            return addr;
        }
    }
    
    // Try direct export lookup
    let addr = Module.findExportByName(nfcModuleName, name);
    if (addr) {
        resolvedSymbols[name] = addr;
        logv('Symbol (export): ' + name + ' @ ' + addr);
        return addr;
    }
    
    // Try symbol enumeration
    try {
        const symbols = Module.enumerateSymbolsSync(nfcModuleName);
        for (const sym of symbols) {
            if (sym.name === name || sym.name.includes(name)) {
                resolvedSymbols[name] = sym.address;
                logv('Symbol (enum): ' + sym.name + ' @ ' + sym.address);
                return sym.address;
            }
        }
    } catch (e) {
        // Symbol enumeration not supported
    }
    
    logv('Symbol not found: ' + name);
    return null;
}

// ============================================================================
// Global Variables
// ============================================================================

let nfa_dm_cb_addr = null;
let nfc_cb_addr = null;
let discStateOffset = -1;

function findGlobalVariables() {
    const mod = findNfcModule();
    if (!mod) return;
    
    // Try to find nfa_dm_cb
    nfa_dm_cb_addr = resolveSymbol('nfa_dm_cb');
    if (nfa_dm_cb_addr) {
        log('✓ nfa_dm_cb @ ' + nfa_dm_cb_addr);
    }
    
    // Try to find nfc_cb
    nfc_cb_addr = resolveSymbol('nfc_cb');
    if (nfc_cb_addr) {
        log('✓ nfc_cb @ ' + nfc_cb_addr);
    }
    
    // Try to determine disc_state offset by scanning
    if (nfa_dm_cb_addr) {
        discStateOffset = findDiscStateOffset();
        if (discStateOffset >= 0) {
            log('✓ disc_state offset: 0x' + discStateOffset.toString(16));
        }
    }
}

function findDiscStateOffset() {
    // Scan nfa_dm_cb for likely disc_state location
    // disc_state should be a value 0-8 (discovery states)
    
    if (!nfa_dm_cb_addr) return -1;
    
    const startOffset = 0x50;  // Skip initial pointers
    const endOffset = 0x100;
    
    for (let offset = startOffset; offset < endOffset; offset++) {
        try {
            const val = nfa_dm_cb_addr.add(offset).readU8();
            // disc_state should be in range 0-8 and followed by other small values
            if (val >= 0 && val <= 8) {
                const next1 = nfa_dm_cb_addr.add(offset + 1).readU8();
                const next2 = nfa_dm_cb_addr.add(offset + 2).readU8();
                // Look for pattern: disc_state followed by reasonable values
                if (next1 <= 0xFF && next2 <= 0xFF) {
                    logv('Candidate disc_state at 0x' + offset.toString(16) + ': ' + val);
                    // Use first reasonable candidate
                    return offset;
                }
            }
        } catch (e) {
            // Read error, continue
        }
    }
    
    // Fall back to default offset
    return CONFIG.DISC_CB_OFFSET_IN_DM_CB + CONFIG.DISC_STATE_OFFSET_IN_DISC_CB;
}

// ============================================================================
// State Manipulation
// ============================================================================

function getDiscoveryState() {
    if (!nfa_dm_cb_addr || discStateOffset < 0) return -1;
    try {
        return nfa_dm_cb_addr.add(discStateOffset).readU8();
    } catch (e) {
        return -1;
    }
}

function setDiscoveryState(newState) {
    if (!nfa_dm_cb_addr || discStateOffset < 0) {
        log('Cannot set state: nfa_dm_cb or offset not found');
        return false;
    }
    
    try {
        const ptr = nfa_dm_cb_addr.add(discStateOffset);
        const oldState = ptr.readU8();
        
        Memory.protect(ptr, 4, 'rwx');
        ptr.writeU8(newState);
        
        logv('State: 0x' + oldState.toString(16) + ' -> 0x' + newState.toString(16));
        return true;
    } catch (e) {
        logError('Failed to set state: ' + e);
        return false;
    }
}

function getStateName(state) {
    const names = {
        0: 'IDLE',
        1: 'DISCOVERY',
        2: 'W4_ALL_DISC',
        3: 'W4_HOST_SELECT',
        4: 'POLL_ACTIVE',
        5: 'LISTEN_ACTIVE',
        6: 'LISTEN_SLEEP',
        7: 'LP_LISTEN',
        8: 'LP_ACTIVE'
    };
    return names[state] || 'UNKNOWN(' + state + ')';
}

// ============================================================================
// Bypass Control
// ============================================================================

let bypassEnabled = false;
let savedState = -1;

function enableBypass() {
    if (bypassEnabled) return true;
    
    savedState = getDiscoveryState();
    if (savedState < 0) {
        logError('Cannot enable bypass: state read failed');
        return false;
    }
    
    const success = setDiscoveryState(CONFIG.NFA_DM_RFST_LISTEN_ACTIVE);
    if (success) {
        bypassEnabled = true;
        log('*** BYPASS ENABLED ***');
        log('  State spoofed: ' + getStateName(savedState) + ' -> LISTEN_ACTIVE');
    }
    return success;
}

function disableBypass() {
    if (!bypassEnabled) return;
    
    if (savedState >= 0) {
        setDiscoveryState(savedState);
        log('  State restored: LISTEN_ACTIVE -> ' + getStateName(savedState));
        savedState = -1;
    }
    bypassEnabled = false;
    log('*** BYPASS DISABLED ***');
}

// ============================================================================
// Hooking
// ============================================================================

let hooksInstalled = false;

function installHooks() {
    if (hooksInstalled) return;
    
    // Hook nfa_dm_act_send_raw_frame for monitoring
    const sendRawFrameAddr = resolveSymbol('nfa_dm_act_send_raw_frame');
    if (sendRawFrameAddr) {
        Interceptor.attach(sendRawFrameAddr, {
            onEnter: function(args) {
                const state = getDiscoveryState();
                log('nfa_dm_act_send_raw_frame called, state=' + getStateName(state));
                this.state = state;
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                log('  -> result: ' + (result ? 'FAILED (buffer freed)' : 'OK (buffer retained)'));
            }
        });
        log('✓ Hooked nfa_dm_act_send_raw_frame');
    }
    
    // Hook NFC_SendData for monitoring
    const nfcSendDataAddr = resolveSymbol('NFC_SendData');
    if (nfcSendDataAddr) {
        Interceptor.attach(nfcSendDataAddr, {
            onEnter: function(args) {
                const connId = args[0].toInt32();
                const pBuf = args[1];
                logv('NFC_SendData: conn_id=' + connId);
                
                if (!pBuf.isNull()) {
                    try {
                        const len = pBuf.add(2).readU16();
                        const offset = pBuf.add(4).readU16();
                        logv('  len=' + len + ', offset=' + offset);
                    } catch (e) {
                        // Read error
                    }
                }
            },
            onLeave: function(retval) {
                logv('  -> status: ' + retval.toInt32());
            }
        });
        log('✓ Hooked NFC_SendData');
    }
    
    hooksInstalled = true;
}

// ============================================================================
// SENSF_RES Building and Sending
// ============================================================================

function buildSensfRes(idm, pmm) {
    // SENSF_RES format (FeliCa/NFC-F):
    // [Length(1B)][Response Code(1B)][IDm(8B)][PMm(8B)][RD(0 or 2B)]
    // 
    // Length field = number of bytes following (NOT including Length itself)
    // Without RD: Length = 1 + 8 + 8 = 17 bytes
    // With RD:    Length = 1 + 8 + 8 + 2 = 19 bytes
    //
    // Total packet size: 1 (Length) + 17 = 18 bytes (without RD)
    const SENSF_RES_LEN = 17; // Response Code + IDm + PMm (no RD)
    const TOTAL_SIZE = 1 + SENSF_RES_LEN; // Length field + payload = 18 bytes
    const buf = Memory.alloc(TOTAL_SIZE);
    let offset = 0;
    
    // Length field (NOT including itself, just the payload)
    buf.add(offset++).writeU8(SENSF_RES_LEN);
    
    // Response code (0x01 for SENSF_RES)
    buf.add(offset++).writeU8(0x01);
    
    // IDm (8 bytes) - Manufacture code + Card ID
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(idm[i] || 0);
    }
    
    // PMm (8 bytes) - IC code + Max response time
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(pmm[i] || 0xFF);
    }
    
    return buf;
}

function sendRawFrame(data, len) {
    const NFA_SendRawFrame = resolveSymbol('NFA_SendRawFrame');
    if (!NFA_SendRawFrame) {
        logError('Cannot send: NFA_SendRawFrame not found');
        return -1;
    }
    
    // NFA_SendRawFrame(uint8_t* p_raw_data, uint16_t data_len, uint16_t presence_check_start_delay)
    const sendFunc = new NativeFunction(NFA_SendRawFrame, 'int', ['pointer', 'uint16', 'uint16']);
    
    const wasEnabled = bypassEnabled;
    if (!wasEnabled) {
        enableBypass();
    }
    
    try {
        const result = sendFunc(data, len, 0);
        logv('NFA_SendRawFrame result: ' + result);
        return result;
    } catch (e) {
        logError('NFA_SendRawFrame exception: ' + e);
        return -1;
    } finally {
        if (!wasEnabled) {
            disableBypass();
        }
    }
}

// ============================================================================
// Spray Mode Implementation
// ============================================================================

function sprayFrame(data, len, count, intervalMs) {
    log('*** SPRAY MODE: ' + count + ' frames @ ' + intervalMs + 'ms intervals ***');
    log('  Data: ' + hexdump_short(data, len));
    
    enableBypass();
    
    const NFA_SendRawFrame = resolveSymbol('NFA_SendRawFrame');
    if (!NFA_SendRawFrame) {
        logError('Cannot spray: NFA_SendRawFrame not found');
        disableBypass();
        return { success: 0, fail: 0 };
    }
    
    const sendFunc = new NativeFunction(NFA_SendRawFrame, 'int', ['pointer', 'uint16', 'uint16']);
    
    let successCount = 0;
    let failCount = 0;
    const startTime = Date.now();
    
    for (let i = 0; i < count; i++) {
        try {
            const result = sendFunc(data, len, 0);
            if (result === 0) {
                successCount++;
            } else {
                failCount++;
            }
        } catch (e) {
            failCount++;
        }
        
        // Log progress every 10 frames
        if ((i + 1) % 10 === 0) {
            log('  Progress: ' + (i + 1) + '/' + count + 
                ' (success: ' + successCount + ', fail: ' + failCount + ')');
        }
        
        // Sleep between frames
        if (i < count - 1) {
            Thread.sleep(intervalMs / 1000);
        }
    }
    
    disableBypass();
    
    const elapsed = Date.now() - startTime;
    log('*** SPRAY COMPLETE ***');
    log('  Total time: ' + elapsed + 'ms');
    log('  Success: ' + successCount + ', Fail: ' + failCount);
    
    return { success: successCount, fail: failCount, elapsed: elapsed };
}

// ============================================================================
// Utility Functions
// ============================================================================

function hexToBytes(hex) {
    if (!hex) return [];
    hex = hex.replace(/\s/g, '');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function bytesToHex(bytes) {
    if (!bytes) return '';
    return bytes.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
}

// ============================================================================
// RPC Exports
// ============================================================================

rpc.exports = {
    /**
     * Send a single SENSF_RES
     * @param idmHex IDm as hex string (16 chars, e.g., "1145141919810000")
     * @param pmmHex PMm as hex string (16 chars, e.g., "FFFFFFFFFFFFFFFF")
     * @returns status code (0 = success)
     */
    sendSensfRes: function(idmHex, pmmHex) {
        log('sendSensfRes: IDm=' + idmHex + ', PMm=' + pmmHex);
        const idm = hexToBytes(idmHex);
        const pmm = hexToBytes(pmmHex);
        const frame = buildSensfRes(idm, pmm);
        return sendRawFrame(frame, 18);
    },
    
    /**
     * Spray SENSF_RES frames
     * @param idmHex IDm as hex string
     * @param pmmHex PMm as hex string  
     * @param count Number of frames to send (default: 100)
     * @param intervalMs Interval between frames in ms (default: 3)
     * @returns {success, fail, elapsed}
     */
    spraySensfRes: function(idmHex, pmmHex, count, intervalMs) {
        log('spraySensfRes: IDm=' + idmHex + ', PMm=' + pmmHex + 
            ', count=' + (count || CONFIG.defaultSprayCount) + 
            ', interval=' + (intervalMs || CONFIG.defaultSprayIntervalMs) + 'ms');
        const idm = hexToBytes(idmHex);
        const pmm = hexToBytes(pmmHex);
        const frame = buildSensfRes(idm, pmm);
        return sprayFrame(frame, 18, 
            count || CONFIG.defaultSprayCount, 
            intervalMs || CONFIG.defaultSprayIntervalMs);
    },
    
    /**
     * Enable state bypass mode
     * @returns true if successful
     */
    enableBypass: function() {
        return enableBypass();
    },
    
    /**
     * Disable state bypass mode
     */
    disableBypass: function() {
        disableBypass();
    },
    
    /**
     * Get current discovery state
     * @returns state value (0-8) or -1 if unknown
     */
    getState: function() {
        const state = getDiscoveryState();
        return { value: state, name: getStateName(state) };
    },
    
    /**
     * Get module and symbol information
     */
    getInfo: function() {
        const mod = findNfcModule();
        return {
            module: nfcModuleName,
            base: mod ? mod.base.toString() : null,
            size: mod ? mod.size : 0,
            nfa_dm_cb: nfa_dm_cb_addr ? nfa_dm_cb_addr.toString() : null,
            nfc_cb: nfc_cb_addr ? nfc_cb_addr.toString() : null,
            discStateOffset: discStateOffset >= 0 ? '0x' + discStateOffset.toString(16) : null,
            currentState: getStateName(getDiscoveryState()),
            bypassEnabled: bypassEnabled,
            hooksInstalled: hooksInstalled
        };
    },
    
    /**
     * Install monitoring hooks
     */
    installHooks: function() {
        installHooks();
        return hooksInstalled;
    }
};

// ============================================================================
// Initialization
// ============================================================================

log('==========================================');
log('  HCE-F Hook - Observe Mode Bypass');
log('  Version: 1.0 (Based on AOSP Analysis)');
log('==========================================');

// Find NFC module
const mod = findNfcModule();
if (!mod) {
    logError('FATAL: Cannot proceed without NFC library');
    logError('Make sure this script is injected into com.android.nfc process');
} else {
    // Find global variables
    findGlobalVariables();
    
    // Install hooks for monitoring
    installHooks();
    
    log('');
    log('Initialization complete');
    log('Current state: ' + getStateName(getDiscoveryState()));
    log('');
    log('=== RPC Interface ===');
    log('  sendSensfRes(idmHex, pmmHex)');
    log('  spraySensfRes(idmHex, pmmHex, count, intervalMs)');
    log('  enableBypass() / disableBypass()');
    log('  getState()');
    log('  getInfo()');
    log('');
    log('=== Example Usage ===');
    log('  // Send single frame');
    log('  rpc.exports.sendSensfRes("1145141919810000", "FFFFFFFFFFFFFFFF")');
    log('');
    log('  // Spray 100 frames @ 3ms');
    log('  rpc.exports.spraySensfRes("1145141919810000", "FFFFFFFFFFFFFFFF", 100, 3)');
}

log('==========================================');
