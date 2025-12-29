/**
 * HCE-F Hook - Frida Script for Observe Mode SENSF_RES Injection
 * 
 * This script bypasses the NFA state machine to allow raw frame transmission
 * in Observe Mode (Discovery state).
 * 
 * Target: Android 14/15, libnfc-nci.so (via libstnfc_nci_jni.so or libnfc_nci_jni.so)
 * 
 * Usage:
 *   frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause
 *   or inject via frida-server
 * 
 * Key Functions Hooked:
 *   - NFC_SendData (for raw data transmission)
 *   - nfa_dm_act_send_raw_frame (state validation bypass)
 *   - ce_t3t_send_to_lower (direct T3T send)
 */

'use strict';

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
    // Library names to search
    libraryNames: [
        'libstnfc_nci_jni.so',    // ST NFC chipset (real devices like Pixel)
        'libnfc_nci_jni.so',      // Standard AOSP
        'libnfc-nci.so'           // Alternative
    ],
    
    // NFA Discovery States
    NFA_DM_RFST_IDLE: 0x00,
    NFA_DM_RFST_DISCOVERY: 0x01,
    NFA_DM_RFST_W4_ALL_DISC: 0x02,
    NFA_DM_RFST_W4_HOST_SELECT: 0x03,
    NFA_DM_RFST_POLL_ACTIVE: 0x04,
    NFA_DM_RFST_LISTEN_ACTIVE: 0x05,
    NFA_DM_RFST_LISTEN_SLEEP: 0x06,
    
    // NFC States
    NFC_STATE_NONE: 0x00,
    NFC_STATE_OPEN: 0x05,
    
    // Logging
    verbose: true,
    
    // Spray mode settings
    sprayEnabled: false,
    sprayIntervalMs: 3,
    sprayCount: 100
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

function hexdump_short(ptr, len) {
    if (!ptr || len <= 0) return '(null)';
    let result = '';
    for (let i = 0; i < Math.min(len, 32); i++) {
        result += ('0' + (ptr.add(i).readU8() & 0xFF).toString(16)).slice(-2) + ' ';
    }
    if (len > 32) result += '...';
    return result.trim();
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
                log('Found NFC library: ' + libName + ' at ' + mod.base);
                log('  Size: ' + mod.size + ' bytes');
                return mod;
            }
        } catch (e) {
            // Module not found
        }
    }
    
    log('ERROR: No NFC library found');
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
    
    // Try direct export lookup
    let addr = Module.findExportByName(nfcModuleName, name);
    if (addr) {
        resolvedSymbols[name] = addr;
        logv('Found symbol (export): ' + name + ' at ' + addr);
        return addr;
    }
    
    // Try symbol enumeration
    const symbols = Module.enumerateSymbolsSync(nfcModuleName);
    for (const sym of symbols) {
        if (sym.name === name || sym.name.includes(name)) {
            resolvedSymbols[name] = sym.address;
            logv('Found symbol (enum): ' + sym.name + ' at ' + sym.address);
            return sym.address;
        }
    }
    
    logv('Symbol not found: ' + name);
    return null;
}

// ============================================================================
// Global Variables
// ============================================================================

let nfa_dm_cb = null;
let nfc_cb = null;

function findGlobalVariables() {
    // Try to find nfa_dm_cb
    nfa_dm_cb = resolveSymbol('nfa_dm_cb');
    if (nfa_dm_cb) {
        log('nfa_dm_cb found at: ' + nfa_dm_cb);
    }
    
    // Try to find nfc_cb
    nfc_cb = resolveSymbol('nfc_cb');
    if (nfc_cb) {
        log('nfc_cb found at: ' + nfc_cb);
    }
}

// ============================================================================
// State Manipulation
// ============================================================================

// Structure offsets (may vary by build - these are typical values)
const OFFSETS = {
    // nfa_dm_cb offsets
    disc_cb: 0x00,           // disc_cb structure offset
    disc_state: 0x00,        // disc_state within disc_cb (typically at start)
    
    // nfc_cb offsets  
    nfc_state: 0x00          // nfc_state at start of nfc_cb
};

function getDiscoveryState() {
    if (!nfa_dm_cb) return -1;
    try {
        const state = nfa_dm_cb.add(OFFSETS.disc_cb + OFFSETS.disc_state).readU8();
        return state;
    } catch (e) {
        return -1;
    }
}

function setDiscoveryState(newState) {
    if (!nfa_dm_cb) {
        log('Cannot set state: nfa_dm_cb not found');
        return false;
    }
    
    try {
        const ptr = nfa_dm_cb.add(OFFSETS.disc_cb + OFFSETS.disc_state);
        const oldState = ptr.readU8();
        
        Memory.protect(ptr, 4, 'rwx');
        ptr.writeU8(newState);
        
        log('State changed: 0x' + oldState.toString(16) + ' -> 0x' + newState.toString(16));
        return true;
    } catch (e) {
        log('Failed to set state: ' + e);
        return false;
    }
}

// ============================================================================
// Hooking Functions
// ============================================================================

let bypassEnabled = false;
let savedState = -1;

function enableBypass() {
    if (bypassEnabled) return;
    
    savedState = getDiscoveryState();
    if (savedState >= 0) {
        setDiscoveryState(CONFIG.NFA_DM_RFST_LISTEN_ACTIVE);
    }
    bypassEnabled = true;
    log('*** BYPASS ENABLED ***');
}

function disableBypass() {
    if (!bypassEnabled) return;
    
    if (savedState >= 0) {
        setDiscoveryState(savedState);
        savedState = -1;
    }
    bypassEnabled = false;
    log('*** BYPASS DISABLED ***');
}

function hookNFCSendData() {
    const addr = resolveSymbol('NFC_SendData');
    if (!addr) {
        log('NFC_SendData not found - trying alternative symbols');
        return false;
    }
    
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const connId = args[0].toInt32();
            const pBuf = args[1];
            
            if (pBuf.isNull()) {
                this.skip = true;
                return;
            }
            
            // BT_HDR structure: event(2), len(2), offset(2), layer_specific(2), data...
            const len = pBuf.add(2).readU16();
            const offset = pBuf.add(4).readU16();
            const data = pBuf.add(8 + offset);
            
            logv('NFC_SendData: conn=' + connId + ', len=' + len);
            logv('  Data: ' + hexdump_short(data, len));
            
            this.connId = connId;
            this.len = len;
        },
        onLeave: function(retval) {
            if (this.skip) return;
            const status = retval.toInt32();
            logv('NFC_SendData returned: ' + status);
            
            if (status !== 0 && bypassEnabled) {
                log('NFC_SendData failed with bypass - may need deeper hook');
            }
        }
    });
    
    log('Hooked NFC_SendData');
    return true;
}

function hookCeT3tSendToLower() {
    // ce_t3t_send_to_lower is the T3T (FeliCa) specific send function
    const addr = resolveSymbol('ce_t3t_send_to_lower');
    if (!addr) {
        logv('ce_t3t_send_to_lower not found');
        return false;
    }
    
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const pBuf = args[0];
            log('ce_t3t_send_to_lower called');
            
            if (!pBuf.isNull()) {
                const len = pBuf.add(2).readU16();
                const offset = pBuf.add(4).readU16();
                const data = pBuf.add(8 + offset);
                log('  T3T Data: ' + hexdump_short(data, len));
            }
        },
        onLeave: function(retval) {
            log('ce_t3t_send_to_lower returned: ' + retval);
        }
    });
    
    log('Hooked ce_t3t_send_to_lower');
    return true;
}

function hookNfaDmActSendRawFrame() {
    // This is the key function that blocks TX in wrong states
    const addr = resolveSymbol('nfa_dm_act_send_raw_frame');
    if (!addr) {
        logv('nfa_dm_act_send_raw_frame not found');
        return false;
    }
    
    Interceptor.attach(addr, {
        onEnter: function(args) {
            log('nfa_dm_act_send_raw_frame called');
            
            if (bypassEnabled) {
                // The state check happens at the start of this function
                // We've already spoofed the state, so it should pass
                log('  Bypass active - state should be spoofed');
            }
        },
        onLeave: function(retval) {
            const result = retval.toInt32();
            log('nfa_dm_act_send_raw_frame returned: ' + result);
        }
    });
    
    log('Hooked nfa_dm_act_send_raw_frame');
    return true;
}

// ============================================================================
// SENSF_RES Building and Sending
// ============================================================================

function buildSensfRes(idm, pmm) {
    // SENSF_RES: [Length][0x01][IDm 8B][PMm 8B]
    // Total: 1 + 1 + 8 + 8 = 18 bytes
    const buf = Memory.alloc(18);
    let offset = 0;
    
    // Length (including length byte)
    buf.add(offset++).writeU8(18);
    
    // Response code
    buf.add(offset++).writeU8(0x01);
    
    // IDm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(idm[i] || 0);
    }
    
    // PMm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(pmm[i] || 0xFF);
    }
    
    return buf;
}

function sendRawFrame(data, len) {
    const NFA_SendRawFrame = resolveSymbol('NFA_SendRawFrame');
    if (!NFA_SendRawFrame) {
        log('Cannot send: NFA_SendRawFrame not found');
        return -1;
    }
    
    const sendFunc = new NativeFunction(NFA_SendRawFrame, 'int', ['pointer', 'uint16', 'uint16']);
    
    enableBypass();
    
    try {
        const result = sendFunc(data, len, 0);
        log('NFA_SendRawFrame result: ' + result);
        return result;
    } finally {
        disableBypass();
    }
}

// ============================================================================
// Spray Mode Implementation
// ============================================================================

function sprayFrame(data, len, count, intervalMs) {
    log('*** SPRAY MODE: ' + count + ' frames @ ' + intervalMs + 'ms intervals ***');
    
    enableBypass();
    
    const NFA_SendRawFrame = resolveSymbol('NFA_SendRawFrame');
    if (!NFA_SendRawFrame) {
        log('Cannot spray: NFA_SendRawFrame not found');
        disableBypass();
        return;
    }
    
    const sendFunc = new NativeFunction(NFA_SendRawFrame, 'int', ['pointer', 'uint16', 'uint16']);
    
    let successCount = 0;
    let failCount = 0;
    
    for (let i = 0; i < count; i++) {
        const result = sendFunc(data, len, 0);
        if (result === 0) {
            successCount++;
        } else {
            failCount++;
        }
        
        // Log progress every 10 frames
        if ((i + 1) % 10 === 0) {
            log('Spray progress: ' + (i + 1) + '/' + count + ' (success: ' + successCount + ', fail: ' + failCount + ')');
        }
        
        // Sleep between frames
        if (i < count - 1) {
            Thread.sleep(intervalMs / 1000);
        }
    }
    
    disableBypass();
    
    log('*** SPRAY COMPLETE: success=' + successCount + ', fail=' + failCount + ' ***');
}

// ============================================================================
// RPC Exports
// ============================================================================

rpc.exports = {
    /**
     * Send a single SENSF_RES
     * @param idmHex IDm as hex string (16 chars)
     * @param pmmHex PMm as hex string (16 chars)
     */
    sendSensfRes: function(idmHex, pmmHex) {
        const idm = hexToBytes(idmHex);
        const pmm = hexToBytes(pmmHex);
        const frame = buildSensfRes(idm, pmm);
        return sendRawFrame(frame, 18);
    },
    
    /**
     * Spray SENSF_RES frames
     * @param idmHex IDm as hex string
     * @param pmmHex PMm as hex string  
     * @param count Number of frames to send
     * @param intervalMs Interval between frames in ms
     */
    spraySensfRes: function(idmHex, pmmHex, count, intervalMs) {
        const idm = hexToBytes(idmHex);
        const pmm = hexToBytes(pmmHex);
        const frame = buildSensfRes(idm, pmm);
        sprayFrame(frame, 18, count || 100, intervalMs || 3);
    },
    
    /**
     * Enable bypass mode
     */
    enableBypass: function() {
        enableBypass();
    },
    
    /**
     * Disable bypass mode
     */
    disableBypass: function() {
        disableBypass();
    },
    
    /**
     * Get current discovery state
     */
    getState: function() {
        return getDiscoveryState();
    },
    
    /**
     * Get module info
     */
    getInfo: function() {
        const mod = findNfcModule();
        return {
            module: nfcModuleName,
            base: mod ? mod.base.toString() : null,
            nfa_dm_cb: nfa_dm_cb ? nfa_dm_cb.toString() : null,
            nfc_cb: nfc_cb ? nfc_cb.toString() : null,
            state: getDiscoveryState(),
            bypassEnabled: bypassEnabled
        };
    }
};

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// ============================================================================
// Initialization
// ============================================================================

log('==========================================');
log('  HCE-F Hook - Observe Mode Bypass Script');
log('==========================================');

// Find NFC module
const mod = findNfcModule();
if (!mod) {
    log('FATAL: Cannot proceed without NFC library');
} else {
    // Find global variables
    findGlobalVariables();
    
    // Install hooks
    hookNFCSendData();
    hookNfaDmActSendRawFrame();
    hookCeT3tSendToLower();
    
    log('Initialization complete');
    log('Use rpc.exports to interact:');
    log('  - sendSensfRes(idmHex, pmmHex)');
    log('  - spraySensfRes(idmHex, pmmHex, count, intervalMs)');
    log('  - enableBypass() / disableBypass()');
    log('  - getState()');
    log('  - getInfo()');
}

log('==========================================');
