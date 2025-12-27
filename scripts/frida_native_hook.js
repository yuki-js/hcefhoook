/**
 * HCE-F Hook - Frida Script for Native Layer Bypass
 * 
 * This script hooks the native libnfc-nci.so functions that the Xposed
 * module cannot reach. Use this in conjunction with the Xposed module
 * for complete SENSF_RES injection capability.
 * 
 * Usage:
 *   frida -U -f com.android.nfc -l frida_native_hook.js --no-pause
 * 
 * Or attach to running NFC service:
 *   frida -U com.android.nfc -l frida_native_hook.js
 */

'use strict';

const LIBNFC = "libnfc-nci.so";

// State constants
const NFA_DM_RFST_IDLE = 0x00;
const NFA_DM_RFST_DISCOVERY = 0x01;
const NFA_DM_RFST_LISTEN_ACTIVE = 0x05;

// SENSF_RES command code
const SENSF_RES_CMD = 0x01;

// Default injection parameters
const DEFAULT_IDM = [0x11, 0x45, 0x14, 0x19, 0x19, 0x81, 0x00, 0x00];
const DEFAULT_PMM = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

// Global state
let nfaDmCbAddr = null;
let bypassEnabled = false;
let pendingInjection = null;

console.log("===========================================");
console.log("  HCE-F Hook - Frida Native Bypass Script");
console.log("===========================================\n");

/**
 * Find nfa_dm_cb global variable address
 */
function findNfaDmCb() {
    const libnfc = Process.findModuleByName(LIBNFC);
    if (!libnfc) {
        console.log("[-] libnfc-nci.so not found");
        return null;
    }
    
    console.log("[*] libnfc-nci.so loaded at: " + libnfc.base);
    
    // Search for nfa_dm_cb symbol
    const symbols = Module.enumerateSymbols(LIBNFC);
    for (const sym of symbols) {
        if (sym.name.includes("nfa_dm_cb")) {
            console.log("[+] Found nfa_dm_cb at: " + sym.address);
            return sym.address;
        }
    }
    
    console.log("[-] nfa_dm_cb symbol not found");
    return null;
}

/**
 * Hook nfa_dm_is_data_exchange_allowed() to bypass state check
 */
function hookStateCheck() {
    const libnfc = Process.findModuleByName(LIBNFC);
    if (!libnfc) return false;
    
    const symbols = Module.enumerateSymbols(LIBNFC);
    
    for (const sym of symbols) {
        if (sym.name.includes("is_data_exchange_allowed") || 
            sym.name.includes("data_exchange")) {
            
            console.log("[+] Hooking: " + sym.name + " at " + sym.address);
            
            Interceptor.attach(sym.address, {
                onEnter: function(args) {
                    // Nothing to do on entry
                },
                onLeave: function(retval) {
                    if (bypassEnabled) {
                        console.log("[*] Bypass: Forcing data_exchange_allowed = true");
                        retval.replace(1);
                    }
                }
            });
            return true;
        }
    }
    
    console.log("[-] is_data_exchange_allowed function not found");
    return false;
}

/**
 * Hook NFA_SendRawFrame to inject SENSF_RES
 */
function hookSendRawFrame() {
    const sendRawFrame = Module.findExportByName(LIBNFC, "NFA_SendRawFrame");
    
    if (sendRawFrame) {
        console.log("[+] Found NFA_SendRawFrame at: " + sendRawFrame);
        
        Interceptor.attach(sendRawFrame, {
            onEnter: function(args) {
                const data = args[0];
                const len = args[1].toInt32();
                console.log("[*] NFA_SendRawFrame called, len=" + len);
                console.log("[*] Data: " + hexdump(data, { length: Math.min(len, 32) }));
            },
            onLeave: function(retval) {
                console.log("[*] NFA_SendRawFrame returned: " + retval);
            }
        });
        return true;
    } else {
        console.log("[-] NFA_SendRawFrame not found");
        return false;
    }
}

/**
 * Hook polling frame notification to detect SENSF_REQ
 */
function hookPollingFrameNotification() {
    const libnfc = Process.findModuleByName(LIBNFC);
    if (!libnfc) return false;
    
    const symbols = Module.enumerateSymbols(LIBNFC);
    
    // Look for polling frame handling functions
    const targetPatterns = [
        "polling_frame",
        "poll_loop",
        "android_polling",
        "sensf_req"
    ];
    
    for (const sym of symbols) {
        for (const pattern of targetPatterns) {
            if (sym.name.toLowerCase().includes(pattern)) {
                console.log("[+] Potential polling hook: " + sym.name + " at " + sym.address);
                
                try {
                    Interceptor.attach(sym.address, {
                        onEnter: function(args) {
                            console.log("[*] " + sym.name + " called");
                        }
                    });
                } catch (e) {
                    console.log("[-] Could not hook " + sym.name + ": " + e);
                }
            }
        }
    }
    
    return true;
}

/**
 * Build SENSF_RES frame
 */
function buildSensfRes(idm, pmm) {
    const buf = Memory.alloc(19);
    let offset = 0;
    
    // Length byte (total frame size)
    buf.add(offset++).writeU8(18);
    
    // Response code
    buf.add(offset++).writeU8(SENSF_RES_CMD);
    
    // IDm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(idm[i]);
    }
    
    // PMm (8 bytes)
    for (let i = 0; i < 8; i++) {
        buf.add(offset++).writeU8(pmm[i]);
    }
    
    return { buffer: buf, length: 18 };
}

/**
 * Inject SENSF_RES frame
 */
function injectSensfRes(idm, pmm) {
    console.log("[*] Starting SENSF_RES injection...");
    
    // Enable bypass
    bypassEnabled = true;
    
    // Build SENSF_RES
    const sensfRes = buildSensfRes(idm || DEFAULT_IDM, pmm || DEFAULT_PMM);
    console.log("[*] Built SENSF_RES: " + hexdump(sensfRes.buffer, { length: sensfRes.length }));
    
    // Try to call NFA_SendRawFrame
    const sendRawFrame = Module.findExportByName(LIBNFC, "NFA_SendRawFrame");
    if (sendRawFrame) {
        const NFA_SendRawFrame = new NativeFunction(sendRawFrame, 
            'uint8', ['pointer', 'uint16', 'uint16']);
        
        const result = NFA_SendRawFrame(sensfRes.buffer, sensfRes.length, 0);
        console.log("[*] NFA_SendRawFrame result: " + result);
    } else {
        console.log("[-] NFA_SendRawFrame not available");
    }
    
    // Disable bypass
    bypassEnabled = false;
}

/**
 * Enumerate all exports for debugging
 */
function listExports() {
    const libnfc = Process.findModuleByName(LIBNFC);
    if (!libnfc) {
        console.log("[-] libnfc-nci.so not found");
        return;
    }
    
    console.log("\n[*] Exports in libnfc-nci.so:\n");
    
    const exports = Module.enumerateExports(LIBNFC);
    const nfaExports = exports.filter(e => 
        e.name.toLowerCase().includes("nfa") ||
        e.name.toLowerCase().includes("nci") ||
        e.name.toLowerCase().includes("send") ||
        e.name.toLowerCase().includes("data")
    );
    
    nfaExports.forEach(e => {
        console.log("  " + e.type + ": " + e.name + " @ " + e.address);
    });
}

// Initialize hooks
function init() {
    console.log("[*] Initializing hooks...\n");
    
    // Wait for libnfc to load
    const checkModule = setInterval(() => {
        const libnfc = Process.findModuleByName(LIBNFC);
        if (libnfc) {
            clearInterval(checkModule);
            
            nfaDmCbAddr = findNfaDmCb();
            hookStateCheck();
            hookSendRawFrame();
            hookPollingFrameNotification();
            
            console.log("\n[+] Hooks installed successfully!");
            console.log("[*] Use rpc.exports.inject() to inject SENSF_RES");
            console.log("[*] Use rpc.exports.listExports() to see available functions\n");
        }
    }, 100);
}

// RPC exports for external control
rpc.exports = {
    inject: function(idmHex, pmmHex) {
        const idm = idmHex ? hexToBytes(idmHex) : DEFAULT_IDM;
        const pmm = pmmHex ? hexToBytes(pmmHex) : DEFAULT_PMM;
        injectSensfRes(idm, pmm);
    },
    
    enableBypass: function() {
        bypassEnabled = true;
        console.log("[*] Bypass enabled");
    },
    
    disableBypass: function() {
        bypassEnabled = false;
        console.log("[*] Bypass disabled");
    },
    
    listExports: listExports
};

// Utility function
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return bytes;
}

// Start initialization
init();
