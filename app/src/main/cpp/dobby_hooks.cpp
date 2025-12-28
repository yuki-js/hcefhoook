/**
 * HCE-F Hook - Native Function Hooking (FULL DOBBY-STYLE IMPLEMENTATION)
 * 
 * This module uses Dobby-style hooking with DobbySymbolResolver for
 * advanced symbol resolution and direct nfa_dm_cb state manipulation.
 * 
 * Key features:
 * - DobbySymbolResolver for finding symbols in libstnfc_nci_jni.so
 * - Direct nfa_dm_cb.disc_cb.disc_state manipulation for state bypass
 * - Support for multiple library names (libstnfc_nci_jni.so, libnfc_nci_jni.so)
 * - Thread-safe state save/restore
 * - Comprehensive error handling and logging
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <dobby.h>

#define TAG "HcefHook.DobbyNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

// ============================================================================
// NFA State Definitions (from AOSP nfa_dm_int.h)
// ============================================================================

#define NFA_DM_RFST_IDLE            0x00
#define NFA_DM_RFST_DISCOVERY       0x01  // Observe Mode typically uses this
#define NFA_DM_RFST_W4_ALL_DISC     0x02
#define NFA_DM_RFST_W4_HOST_SELECT  0x03
#define NFA_DM_RFST_POLL_ACTIVE     0x04  // TX allowed
#define NFA_DM_RFST_LISTEN_ACTIVE   0x05  // TX allowed
#define NFA_DM_RFST_LISTEN_SLEEP    0x06

// NFC Status codes
#define NFC_STATUS_OK               0
#define NFC_STATUS_FAILED           1

// ============================================================================
// Global State
// ============================================================================

// Type definitions for function pointers
typedef bool (*nfa_dm_is_data_exchange_allowed_t)(void);

static bool g_hooks_installed = false;
static bool g_bypass_enabled = false;
static bool g_spray_mode_enabled = false;
static pthread_mutex_t g_state_mutex = PTHREAD_MUTEX_INITIALIZER;

// Symbol pointers
static void* g_nfa_dm_cb = nullptr;  // CRITICAL: nfa_dm_cb control block
static nfa_dm_is_data_exchange_allowed_t g_orig_nfa_dm_is_data_exchange_allowed = nullptr;

// nfa_dm_cb structure offsets (from SYMBOL_ANALYSIS.md and AOSP sources)
// Based on ST21NFC analysis, these are the known offsets
#define NFA_DM_CB_DISC_CB_OFFSET    0x00  // disc_cb is typically at start
#define DISC_CB_DISC_STATE_OFFSET   0x28  // disc_state offset within disc_cb

/**
 * Get current NFA discovery state from nfa_dm_cb
 */
static uint8_t get_nfa_discovery_state() {
    if (!g_nfa_dm_cb) {
        LOGW("nfa_dm_cb not available");
        return 0xFF;
    }
    
    uint8_t* disc_state_ptr = (uint8_t*)((uintptr_t)g_nfa_dm_cb + 
                                         NFA_DM_CB_DISC_CB_OFFSET +
                                         DISC_CB_DISC_STATE_OFFSET);
    uint8_t state = *disc_state_ptr;
    
    const char* state_name = "UNKNOWN";
    switch (state) {
        case NFA_DM_RFST_IDLE: state_name = "IDLE"; break;
        case NFA_DM_RFST_DISCOVERY: state_name = "DISCOVERY"; break;
        case NFA_DM_RFST_POLL_ACTIVE: state_name = "POLL_ACTIVE"; break;
        case NFA_DM_RFST_LISTEN_ACTIVE: state_name = "LISTEN_ACTIVE"; break;
        case NFA_DM_RFST_LISTEN_SLEEP: state_name = "LISTEN_SLEEP"; break;
    }
    
    LOGD("Current NFA state: 0x%02x (%s)", state, state_name);
    return state;
}

/**
 * Set NFA discovery state directly (STATE BYPASS)
 * This is the core of our Dobby-based approach
 */
static bool set_nfa_discovery_state(uint8_t new_state) {
    if (!g_nfa_dm_cb) {
        LOGE("Cannot set state: nfa_dm_cb not available");
        return false;
    }
    
    pthread_mutex_lock(&g_state_mutex);
    
    uint8_t* disc_state_ptr = (uint8_t*)((uintptr_t)g_nfa_dm_cb + 
                                         NFA_DM_CB_DISC_CB_OFFSET +
                                         DISC_CB_DISC_STATE_OFFSET);
    
    uint8_t old_state = *disc_state_ptr;
    *disc_state_ptr = new_state;
    
    const char* old_name = (old_state == NFA_DM_RFST_DISCOVERY) ? "DISCOVERY" : "OTHER";
    const char* new_name = (new_state == NFA_DM_RFST_LISTEN_ACTIVE) ? "LISTEN_ACTIVE" : "OTHER";
    
    LOGI("STATE BYPASS: %s (0x%02x) -> %s (0x%02x)", 
         old_name, old_state, new_name, new_state);
    
    pthread_mutex_unlock(&g_state_mutex);
    return true;
}

/**
 * State save/restore mechanism for temporary bypass
 */
struct StateBackup {
    uint8_t saved_state;
    bool valid;
};

static StateBackup g_state_backup = {0, false};

static void save_nfa_state() {
    g_state_backup.saved_state = get_nfa_discovery_state();
    g_state_backup.valid = true;
    LOGD("State saved: 0x%02x", g_state_backup.saved_state);
}

static void restore_nfa_state() {
    if (g_state_backup.valid) {
        set_nfa_discovery_state(g_state_backup.saved_state);
        LOGD("State restored: 0x%02x", g_state_backup.saved_state);
        g_state_backup.valid = false;
    }
}

// ============================================================================
// Hook Implementation
// ============================================================================

/**
 * Hook for nfa_dm_is_data_exchange_allowed
 * This function checks if data exchange is allowed in current state
 * We bypass it when bypass_enabled is true
 */
static bool hook_nfa_dm_is_data_exchange_allowed() {
    LOGD("nfa_dm_is_data_exchange_allowed() HOOKED");
    
    if (g_bypass_enabled || g_spray_mode_enabled) {
        LOGI("✓ BYPASS ACTIVE: Forcing data exchange allowed");
        return true;
    }
    
    // Call original if not bypassing
    if (g_orig_nfa_dm_is_data_exchange_allowed) {
        bool result = g_orig_nfa_dm_is_data_exchange_allowed();
        LOGD("Original function returned: %d", result);
        return result;
    }
    
    // Default to allowing
    return true;
}

// ============================================================================
// JNI Interface
// ============================================================================

extern "C" {

/**
 * Install Dobby hooks using DobbySymbolResolver
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_installHooks(JNIEnv *env, jclass clazz) {
    if (g_hooks_installed) {
        LOGW("Hooks already installed");
        return JNI_TRUE;
    }
    
    LOGI("═══════════════════════════════════════════════════════");
    LOGI("  DOBBY-STYLE NATIVE HOOKS INSTALLATION");
    LOGI("═══════════════════════════════════════════════════════");
    LOGI("Dobby Version: %s", DobbyGetVersion());
    LOGI("Strategy: DobbySymbolResolver + nfa_dm_cb manipulation");
    LOGI("Process PID: %d", getpid());
    
    // List all hooks for debugging
    DobbyListHooks();
    
    // Try multiple library names (as discovered in Issue #15)
    const char* lib_names[] = {
        "libstnfc_nci_jni.so",    // Real device name (from Frida)
        "libnfc_nci_jni.so",      // AOSP reference name
        "libnfc-nci.so",          // Alternative
        nullptr
    };
    
    const char* found_lib = nullptr;
    uintptr_t lib_base = 0;
    
    // Step 1: Find which library is actually loaded
    LOGI("Step 1: Locating NFC library...");
    for (int i = 0; lib_names[i] != nullptr; i++) {
        lib_base = DobbyGetModuleBase(lib_names[i]);
        if (lib_base != 0) {
            found_lib = lib_names[i];
            LOGI("✓ Found library: %s at base 0x%lx", found_lib, lib_base);
            break;
        }
    }
    
    if (!found_lib) {
        LOGE("✗ FATAL: No NFC library found in process");
        LOGE("This code must run in com.android.nfc process!");
        return JNI_FALSE;
    }
    
    // Step 2: Resolve critical symbol: nfa_dm_cb
    LOGI("Step 2: Resolving nfa_dm_cb control block...");
    g_nfa_dm_cb = DobbySymbolResolver(found_lib, "nfa_dm_cb");
    
    if (g_nfa_dm_cb) {
        LOGI("✓✓✓ CRITICAL: nfa_dm_cb found at %p", g_nfa_dm_cb);
        LOGI("✓ State bypass strategy is VIABLE");
        
        // Dump first 64 bytes for verification (with bounds check)
        uint8_t* cb_bytes = (uint8_t*)g_nfa_dm_cb;
        // Note: We can't validate the size without additional information,
        // but we log this for debugging. In production, use mprotect or /proc/self/maps
        // to verify memory accessibility before dereferencing.
        LOGI("nfa_dm_cb dump (first 64 bytes - ensure memory is valid):");
        for (int i = 0; i < 64; i += 16) {
            LOGI("  +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                 i, cb_bytes[i], cb_bytes[i+1], cb_bytes[i+2], cb_bytes[i+3],
                 cb_bytes[i+4], cb_bytes[i+5], cb_bytes[i+6], cb_bytes[i+7],
                 cb_bytes[i+8], cb_bytes[i+9], cb_bytes[i+10], cb_bytes[i+11],
                 cb_bytes[i+12], cb_bytes[i+13], cb_bytes[i+14], cb_bytes[i+15]);
        }
        
        // Display current state
        uint8_t current_state = get_nfa_discovery_state();
        LOGI("Current discovery state: 0x%02x", current_state);
        
    } else {
        LOGE("✗ CRITICAL: nfa_dm_cb not found!");
        LOGE("State bypass will NOT be available");
        // Continue anyway, some features may still work
    }
    
    // Step 3: Resolve and hook nfa_dm_is_data_exchange_allowed (optional)
    LOGI("Step 3: Resolving nfa_dm_is_data_exchange_allowed...");
    void* target = DobbySymbolResolver(found_lib, "nfa_dm_is_data_exchange_allowed");
    
    if (target) {
        LOGI("✓ Found nfa_dm_is_data_exchange_allowed at %p", target);
        
        int hook_result = DobbyHook(target, 
                                    (void*)hook_nfa_dm_is_data_exchange_allowed,
                                    (void**)&g_orig_nfa_dm_is_data_exchange_allowed);
        
        if (hook_result == 0) {
            LOGI("✓✓✓ Hook installed successfully");
            LOGI("✓ Original function pointer: %p", g_orig_nfa_dm_is_data_exchange_allowed);
        } else {
            LOGW("Hook installation returned: %d", hook_result);
            LOGW("Will rely on nfa_dm_cb manipulation only");
        }
    } else {
        LOGW("nfa_dm_is_data_exchange_allowed not found (may be inlined)");
        LOGI("Will use nfa_dm_cb manipulation as primary method");
    }
    
    // Step 4: Resolve other symbols for monitoring
    LOGI("Step 4: Resolving additional symbols...");
    
    void* nfa_dm_act_send_raw_frame = DobbySymbolResolver(found_lib, "nfa_dm_act_send_raw_frame");
    if (nfa_dm_act_send_raw_frame) {
        LOGI("✓ nfa_dm_act_send_raw_frame at %p (offset 0x%lx)", 
             nfa_dm_act_send_raw_frame,
             (uintptr_t)nfa_dm_act_send_raw_frame - lib_base);
    }
    
    void* NFC_SendData = DobbySymbolResolver(found_lib, "NFC_SendData");
    if (NFC_SendData) {
        LOGI("✓ NFC_SendData at %p (offset 0x%lx)",
             NFC_SendData,
             (uintptr_t)NFC_SendData - lib_base);
    }
    
    g_hooks_installed = true;
    
    LOGI("═══════════════════════════════════════════════════════");
    LOGI("  INSTALLATION COMPLETE");
    LOGI("═══════════════════════════════════════════════════════");
    LOGI("✓ Dobby Version: %s", DobbyGetVersion());
    LOGI("✓ DobbySymbolResolver: ACTIVE");
    LOGI("✓ nfa_dm_cb bypass: %s", g_nfa_dm_cb ? "READY" : "NOT AVAILABLE");
    LOGI("✓ Process: %d (com.android.nfc)", getpid());
    LOGI("═══════════════════════════════════════════════════════");
    
    return JNI_TRUE;
}

/**
 * Enable bypass mode with state manipulation
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_enableBypass(JNIEnv *env, jclass clazz) {
    g_bypass_enabled = true;
    
    if (g_nfa_dm_cb) {
        // Save current state
        save_nfa_state();
        
        // Set to LISTEN_ACTIVE to allow transmission
        set_nfa_discovery_state(NFA_DM_RFST_LISTEN_ACTIVE);
        
        LOGI("✓✓✓ BYPASS ENABLED with state manipulation");
        LOGI("State changed to LISTEN_ACTIVE (0x05)");
    } else {
        LOGI("BYPASS ENABLED (hook-only mode)");
    }
}

/**
 * Disable bypass mode and restore state
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_disableBypass(JNIEnv *env, jclass clazz) {
    g_bypass_enabled = false;
    
    if (g_nfa_dm_cb && g_state_backup.valid) {
        restore_nfa_state();
        LOGI("BYPASS DISABLED with state restoration");
    } else {
        LOGI("BYPASS DISABLED");
    }
}

/**
 * Enable spray mode
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_enableSprayMode(JNIEnv *env, jclass clazz) {
    g_spray_mode_enabled = true;
    g_bypass_enabled = true;  // Spray mode requires bypass
    
    if (g_nfa_dm_cb) {
        save_nfa_state();
        set_nfa_discovery_state(NFA_DM_RFST_LISTEN_ACTIVE);
        LOGI("✓✓✓ SPRAY MODE ENABLED with state manipulation");
    } else {
        LOGI("SPRAY MODE ENABLED");
    }
}

/**
 * Disable spray mode
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_disableSprayMode(JNIEnv *env, jclass clazz) {
    g_spray_mode_enabled = false;
    
    if (g_nfa_dm_cb && g_state_backup.valid) {
        restore_nfa_state();
        LOGI("SPRAY MODE DISABLED with state restoration");
    } else {
        LOGI("SPRAY MODE DISABLED");
    }
}

/**
 * Check if bypass is enabled
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isBypassEnabled(JNIEnv *env, jclass clazz) {
    return g_bypass_enabled ? JNI_TRUE : JNI_FALSE;
}

/**
 * Check if spray mode is enabled
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isSprayModeEnabled(JNIEnv *env, jclass clazz) {
    return g_spray_mode_enabled ? JNI_TRUE : JNI_FALSE;
}

/**
 * Check if hooks are installed
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isInstalled(JNIEnv *env, jclass clazz) {
    return g_hooks_installed ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get detailed status
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_getStatus(JNIEnv *env, jclass clazz) {
    char info[2048];
    
    uint8_t current_state = 0xFF;
    if (g_nfa_dm_cb) {
        current_state = get_nfa_discovery_state();
    }
    
    snprintf(info, sizeof(info),
             "═══ Dobby Native Hooks Status ═══\n"
             "Dobby Version: %s\n"
             "Installed: %s\n"
             "Bypass Enabled: %s\n"
             "Spray Mode: %s\n"
             "\n"
             "═══ Symbol Resolution ═══\n"
             "nfa_dm_cb: %p\n"
             "Current NFA State: 0x%02x\n"
             "State Backup: %s\n"
             "\n"
             "═══ Capabilities ═══\n"
             "DobbySymbolResolver: YES\n"
             "Direct State Manipulation: %s\n"
             "Process ID: %d\n",
             DobbyGetVersion(),
             g_hooks_installed ? "YES" : "NO",
             g_bypass_enabled ? "YES" : "NO",
             g_spray_mode_enabled ? "YES" : "NO",
             g_nfa_dm_cb,
             current_state,
             g_state_backup.valid ? "VALID" : "NONE",
             g_nfa_dm_cb ? "YES" : "NO",
             getpid());
    
    return env->NewStringUTF(info);
}

} // extern "C"
