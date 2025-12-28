/**
 * HCE-F Hook - Native Function Hooking (DOBBY IMPLEMENTATION)
 * 
 * This module implements runtime native function hooks using Dobby library.
 * It targets libnfc-nci.so and libnfc_nci_jni.so functions that control NFC state
 * and data transmission, enabling SENSF_RES injection in Observe Mode.
 * 
 * CRITICAL: This code MUST execute in the android.nfc process context, not in
 * the hcefhook app package. The Xposed module loads this library into com.android.nfc.
 * 
 * SOLUTION TO LINKER NAMESPACE RESTRICTIONS:
 * ===========================================
 * Android's linker prevents apps from dlopening system libraries due to namespace restrictions.
 * However, this library is loaded into com.android.nfc process via Xposed, where:
 * 1. The NFC libraries are ALREADY loaded into memory
 * 2. We use RTLD_NOLOAD to get handles to already-loaded libraries
 * 3. We parse /proc/self/maps to find library base addresses
 * 4. We use Dobby's DobbyHook() API for professional inline hooking
 * 
 * This completely bypasses the namespace restriction because we're not loading anything new.
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
#include <limits.h>
#include <elf.h>
#include <link.h>
#include <dobby.h>  // Dobby hooking framework

#define TAG "HcefHook.NativeHooks"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

// NFA Discovery states (from nfa_dm_int.h)
#define NFA_DM_RFST_IDLE            0x00
#define NFA_DM_RFST_DISCOVERY       0x01
#define NFA_DM_RFST_W4_ALL_DISC     0x02
#define NFA_DM_RFST_W4_HOST_SELECT  0x03
#define NFA_DM_RFST_POLL_ACTIVE     0x04
#define NFA_DM_RFST_LISTEN_ACTIVE   0x05
#define NFA_DM_RFST_LISTEN_SLEEP    0x06

// NFC Status codes
#define NFC_STATUS_OK               0
#define NFC_STATUS_FAILED           1
#define NFC_STATUS_REJECTED         2

// Global state
static void* libnfc_handle = nullptr;
static void* libnfc_jni_handle = nullptr;
static bool hooks_installed = false;
static bool bypass_enabled = false;
static bool spray_mode_enabled = false;
static char primary_lib_path[PATH_MAX] = {0};
static bool primary_lib_initialized = false;

// Library base addresses (found via /proc/self/maps)
static uintptr_t libnfc_base_addr = 0;
static uintptr_t libnfc_jni_base_addr = 0;

// Function pointers for symbols we want to monitor/hook
typedef bool (*nfa_dm_is_data_exchange_allowed_t)(void);
typedef int (*nfa_dm_act_send_raw_frame_t)(void* p_data);
typedef int (*NFC_SendData_t)(int conn_id, void* p_buf);

static nfa_dm_is_data_exchange_allowed_t orig_nfa_dm_is_data_exchange_allowed = nullptr;
static nfa_dm_act_send_raw_frame_t orig_nfa_dm_act_send_raw_frame = nullptr;
static NFC_SendData_t orig_NFC_SendData = nullptr;

/**
 * Parse /proc/self/maps to find library base address
 * This avoids dlopen and namespace restrictions completely
 */
static uintptr_t find_library_base_address(const char* lib_name) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return 0;
    }
    
    char line[512];
    uintptr_t base_addr = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        // Look for the library in maps
        if (strstr(line, lib_name)) {
            // Parse the address range: "7b12345000-7b12346000 r-xp ..."
            uintptr_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 2) {
                // We want the first r-xp (executable) segment
                if (strstr(perms, "x")) {
                    base_addr = start;
                    LOGI("Found %s base address: 0x%lx", lib_name, base_addr);
                    break;
                }
            }
        }
    }
    fclose(maps);
    
    return base_addr;
}

/**
 * Get handle to already-loaded library using RTLD_NOLOAD
 * This doesn't load anything new, just gets a handle to existing library
 */
static void* get_loaded_library_handle(const char* lib_name) {
    // RTLD_NOLOAD means "don't load, just get handle if already loaded"
    void* handle = dlopen(lib_name, RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        LOGI("Got handle to already-loaded library %s: %p", lib_name, handle);
    } else {
        LOGD("Library %s not loaded or not accessible: %s", lib_name, dlerror());
    }
    return handle;
}

/**
 * Find a symbol in a library using dlsym
 */
static void* find_symbol_in_lib(void* handle, const char* symbol_name) {
    if (!handle) return nullptr;
    
    void* addr = dlsym(handle, symbol_name);
    if (addr) {
        LOGI("Found symbol %s at %p", symbol_name, addr);
    } else {
        LOGD("Symbol %s not found: %s", symbol_name, dlerror());
    }
    return addr;
}

/**
 * Memory protection manipulation for hooking (NOT NEEDED WITH DOBBY)
 * Dobby handles memory protection internally
 */
static bool make_memory_writable(void* addr, size_t len) {
    // Dobby handles this internally, but keep function for compatibility
    uintptr_t page_start = ((uintptr_t)addr) & ~(sysconf(_SC_PAGESIZE) - 1);
    return mprotect((void*)page_start, len + ((uintptr_t)addr - page_start), 
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

/**
 * Install hook using Dobby library
 * This is MUCH more robust than manual ARM64 inline hooking!
 */
static bool install_dobby_hook(void* target, void* hook, void** original) {
    if (!target || !hook) {
        LOGE("Invalid hook parameters");
        return false;
    }
    
    LOGI("Installing Dobby hook: target=%p, hook=%p", target, hook);
    
    // Use Dobby's professional hooking API
    // DobbyHook(target_address, fake_function, &original_function_pointer)
    int result = DobbyHook(target, hook, original);
    
    if (result == 0) {
        LOGI("✓✓✓ Successfully installed Dobby hook for %p", target);
        LOGI("Original function saved at: %p", *original);
        return true;
    } else {
        LOGE("✗ Dobby hook failed with code: %d", result);
        return false;
    }
}

/**
 * Hook function for nfa_dm_is_data_exchange_allowed
 * This function checks if data exchange is allowed in current NFA state
 * We bypass it to always return true when we want to send SENSF_RES
 * 
 * This is a STATE CHECK function - we just bypass the check
 * 
 * With Dobby, we can now properly call the original function if needed!
 */
static bool hook_nfa_dm_is_data_exchange_allowed(void) {
    LOGD("nfa_dm_is_data_exchange_allowed HOOKED - BYPASSING state check");
    
    // Option 1: ALWAYS allow data exchange (bypass mode)
    if (bypass_enabled || spray_mode_enabled) {
        LOGD("Bypass/Spray mode active: Forcing TRUE (allow data exchange)");
        return true;
    }
    
    // Option 2: Call original function when not in bypass mode
    if (orig_nfa_dm_is_data_exchange_allowed) {
        bool result = orig_nfa_dm_is_data_exchange_allowed();
        LOGD("Original function returned: %d", result);
        return result;
    }
    
    // Fallback: Allow by default
    return true;
}

/**
 * Hook function for nfa_dm_act_send_raw_frame
 * This is called when sending raw NFC frames
 * 
 * This is a TRANSMISSION function - we DON'T hook this one
 * Let it execute normally once state checks are bypassed
 */
static int hook_nfa_dm_act_send_raw_frame(void* p_data) {
    // This hook shouldn't be installed - we'll just resolve the symbol
    // The actual work is done by bypassing state checks above
    LOGI("nfa_dm_act_send_raw_frame called (should not be hooked)");
    return NFC_STATUS_FAILED;
}

/**
 * Hook function for NFC_SendData
 * Lower-level send function
 * 
 * This is a TRANSMISSION function - we DON'T hook this one
 */
static int hook_NFC_SendData(int conn_id, void* p_buf) {
    // This hook shouldn't be installed
    LOGI("NFC_SendData called (should not be hooked)");
    return NFC_STATUS_FAILED;
}

/**
 * Resolve function pointers and install REAL hooks using Dobby
 * 
 * This implements actual inline hooking using professional Dobby library!
 * 
 * IMPORTANT: Dobby creates a proper trampoline, so we CAN call original functions
 */
static bool resolve_and_hook_function(void* lib_handle, const char* symbol_name, 
                                      void* hook_func, void** orig_func) {
    void* target = nullptr;

    // Prefer Dobby's built-in symbol resolver when available
    if (primary_lib_initialized) {
        target = DobbySymbolResolver(primary_lib_path, symbol_name);
        if (target) {
            LOGI("DobbySymbolResolver resolved %s at %p", symbol_name, target);
        }
    }

    // Fallback to dlsym if resolver failed
    if (!target) {
        target = find_symbol_in_lib(lib_handle, symbol_name);
    }
    if (!target) {
        LOGW("Cannot resolve %s: symbol not found", symbol_name);
        return false;
    }
    
    LOGI("Resolved %s at %p", symbol_name, target);
    
    // Install real hook if hook_func is provided
    if (hook_func) {
        LOGI("Installing Dobby hook for %s", symbol_name);
        
        if (install_dobby_hook(target, hook_func, orig_func)) {
            LOGI("✓✓✓ Successfully installed Dobby hook for %s", symbol_name);
            LOGI("✓ Original function trampoline at: %p", *orig_func);
            LOGI("✓ Can safely call original function from hook!");
            return true;
        } else {
            LOGE("✗ Failed to install Dobby hook for %s", symbol_name);
            // Save the target address anyway for manual calling
            *orig_func = target;
            return false;
        }
    } else {
        // No hook function provided, just save the address
        *orig_func = target;
        LOGI("Saved function pointer for %s (no hook installed)", symbol_name);
        return true;
    }
}

/**
 * Install hooks using proper address resolution
 * 
 * STRATEGY TO BYPASS LINKER NAMESPACE RESTRICTIONS:
 * ===================================================
 * 1. This code runs in com.android.nfc process (via Xposed injection)
 * 2. NFC libraries are ALREADY loaded in that process
 * 3. Use RTLD_NOLOAD to get handles without loading
 * 4. Use /proc/self/maps to find base addresses
 * 5. Calculate function addresses from base + known offsets
 * 
 * This completely avoids dlopen restrictions!
 */
extern "C" {

JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_installHooks(JNIEnv *env, jclass clazz) {
    if (hooks_installed) {
        LOGW("Hooks already installed");
        return JNI_TRUE;
    }
    
    LOGI("=== Installing Native Hooks ===");
    LOGI("Process: %d (%s)", getpid(), "com.android.nfc expected");
    LOGI("Strategy: RTLD_NOLOAD + /proc/self/maps parsing");
    LOGI("This bypasses linker namespace restrictions completely");
    
    // Step 1: Find loaded NFC libraries in /proc/self/maps
    LOGI("=== Step 1: Enumerating loaded modules ===");
    
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return JNI_FALSE;
    }
    
    char line[512];
    char nfc_lib_path[256] = {0};
    char nfc_jni_lib_path[256] = {0};
    bool found_nfc_lib = false;
    bool found_jni_lib = false;
    
    while (fgets(line, sizeof(line), maps)) {
        // Look for shared libraries (.so) with "nfc" in the name
        if (strstr(line, ".so") && strstr(line, "nfc")) {
            // Extract full library path from maps line
            char* lib_path_start = strchr(line, '/');
            if (lib_path_start) {
                char temp_path[256];
                int i = 0;
                while (lib_path_start[i] && lib_path_start[i] != '\n' && lib_path_start[i] != ' ' && i < 255) {
                    temp_path[i] = lib_path_start[i];
                    i++;
                }
                temp_path[i] = '\0';
                
                // Prefer JNI library
                if (strstr(temp_path, "jni") && !found_jni_lib) {
                    strncpy(nfc_jni_lib_path, temp_path, sizeof(nfc_jni_lib_path) - 1);
                    found_jni_lib = true;
                    LOGI("✓ Found NFC JNI library in memory: %s", nfc_jni_lib_path);
                }
                // Also keep track of non-JNI NFC library
                else if (!found_nfc_lib) {
                    strncpy(nfc_lib_path, temp_path, sizeof(nfc_lib_path) - 1);
                    found_nfc_lib = true;
                    LOGI("✓ Found NFC library in memory: %s", nfc_lib_path);
                }
            }
        }
    }
    fclose(maps);
    
    if (!found_jni_lib && !found_nfc_lib) {
        LOGE("✗ No NFC library found in loaded modules");
        LOGE("This should not happen in com.android.nfc process!");
        return JNI_FALSE;
    }
    
    // Step 2: Get handles using RTLD_NOLOAD (doesn't actually load, just gets handle)
    LOGI("=== Step 2: Getting handles with RTLD_NOLOAD ===");
    
    const char* primary_lib = found_jni_lib ? nfc_jni_lib_path : nfc_lib_path;
    LOGI("Primary library: %s", primary_lib);
    size_t lib_len = strlen(primary_lib);
    if (lib_len >= sizeof(primary_lib_path)) {
        LOGE("Primary library path too long (%zu bytes), cannot use DobbySymbolResolver safely", lib_len);
        primary_lib_initialized = false;
        primary_lib_path[0] = '\0';
    } else {
        snprintf(primary_lib_path, sizeof(primary_lib_path), "%s", primary_lib);
        primary_lib_initialized = true;
    }
    
    // Try RTLD_NOLOAD - this gets a handle to already-loaded library
    libnfc_jni_handle = dlopen(primary_lib, RTLD_NOW | RTLD_NOLOAD);
    if (libnfc_jni_handle) {
        LOGI("✓ Got handle via RTLD_NOLOAD: %p", libnfc_jni_handle);
    } else {
        LOGW("RTLD_NOLOAD failed: %s", dlerror());
        LOGI("Falling back to base address calculation");
        
        // Fallback: Use base address from /proc/self/maps
        const char* lib_name_only = strrchr(primary_lib, '/');
        lib_name_only = lib_name_only ? lib_name_only + 1 : primary_lib;
        
        libnfc_jni_base_addr = find_library_base_address(lib_name_only);
        if (libnfc_jni_base_addr == 0) {
            LOGE("✗ Failed to find library base address");
            return JNI_FALSE;
        }
        LOGI("✓ Using base address: 0x%lx", libnfc_jni_base_addr);
    }
    
    // Use the same handle for both
    libnfc_handle = libnfc_jni_handle;
    
    // Step 3: Resolve function pointers and install REAL hooks using Dobby
    LOGI("=== Step 3: Installing REAL Dobby Hooks ===");
    LOGI("DOBBY VERSION: %s", DobbyGetVersion());
    LOGI("STRATEGY: Only hook STATE CHECK functions, not transmission functions");
    LOGI("This allows the real send functions to work once state checks are bypassed");
    LOGI("WITH DOBBY: Proper trampolines allow calling original functions!");
    bool success = true;
    
    LOGI("=== Symbol Resolution and Selective Hooking ===");
    
    // Function 1: nfa_dm_is_data_exchange_allowed (STATE CHECK - HOOK THIS)
    LOGI("Hook target #1: nfa_dm_is_data_exchange_allowed (STATE CHECK)");
    bool hook1_success = resolve_and_hook_function(
        libnfc_handle, "nfa_dm_is_data_exchange_allowed",
        (void*)hook_nfa_dm_is_data_exchange_allowed,
        (void**)&orig_nfa_dm_is_data_exchange_allowed);
    
    if (hook1_success && orig_nfa_dm_is_data_exchange_allowed) {
        LOGI("✓✓✓ STATE CHECK HOOK INSTALLED: nfa_dm_is_data_exchange_allowed");
        LOGI("This will bypass NFA state machine restrictions");
    } else {
        LOGW("✗ nfa_dm_is_data_exchange_allowed not found (may be inlined)");
        LOGW("Will rely on state spoofing as fallback");
    }
    
    // Function 2: nfa_dm_act_send_raw_frame (TRANSMISSION - DON'T HOOK, JUST RESOLVE)
    LOGI("Symbol resolution #1: nfa_dm_act_send_raw_frame (keep original)");
    resolve_and_hook_function(
        libnfc_handle, "nfa_dm_act_send_raw_frame",
        nullptr,  // Don't install hook - just resolve symbol
        (void**)&orig_nfa_dm_act_send_raw_frame);
    
    if (orig_nfa_dm_act_send_raw_frame) {
        LOGI("✓ TRANSMISSION FUNCTION: nfa_dm_act_send_raw_frame resolved (not hooked)");
    } else {
        LOGE("✗ CRITICAL: Failed to resolve nfa_dm_act_send_raw_frame!");
        success = false;
    }
    
    // Function 3: NFC_SendData (TRANSMISSION - DON'T HOOK, JUST RESOLVE)
    LOGI("Symbol resolution #2: NFC_SendData (keep original)");
    resolve_and_hook_function(
        libnfc_handle, "NFC_SendData",
        nullptr,  // Don't install hook - just resolve symbol
        (void**)&orig_NFC_SendData);
    
    if (orig_NFC_SendData) {
        LOGI("✓ TRANSMISSION FUNCTION: NFC_SendData resolved (not hooked)");
    } else {
        LOGW("✗ NFC_SendData not found, trying alternatives...");
        // Try alternative names
        resolve_and_hook_function(libnfc_handle, "nfc_ncif_send_data",
                                 nullptr,
                                 (void**)&orig_NFC_SendData);
    }
    
    LOGI("=== State Control Block Search ===");
    
    // CRITICAL: Find nfa_dm_cb for state spoofing (identified in SYMBOL_ANALYSIS.md)
    void* nfa_dm_cb = dlsym(libnfc_handle, "nfa_dm_cb");
    if (nfa_dm_cb) {
        LOGI("✓ CRITICAL: Found nfa_dm_cb at %p", nfa_dm_cb);
        LOGI("✓ State spoofing strategy is VIABLE (as backup)");
        LOGI("✓ Can manipulate disc_cb.disc_state for bypass if hooks fail");
        
        // Log the first few bytes for verification
        uint8_t* cb_bytes = (uint8_t*)nfa_dm_cb;
        LOGI("nfa_dm_cb first 32 bytes:");
        for (int i = 0; i < 32; i += 8) {
            LOGI("  +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x",
                 i, cb_bytes[i], cb_bytes[i+1], cb_bytes[i+2], cb_bytes[i+3],
                 cb_bytes[i+4], cb_bytes[i+5], cb_bytes[i+6], cb_bytes[i+7]);
        }
    } else {
        LOGE("✗ CRITICAL: nfa_dm_cb not found - cannot perform state spoofing!");
        LOGE("✗ State bypass strategy NOT available");
    }
    
    hooks_installed = true;
    LOGI("=== Native Hooks Installation Complete ===");
    LOGI("✓✓✓ USING DOBBY LIBRARY v%s", DobbyGetVersion());
    LOGI("✓✓✓ Professional inline hooking with trampolines");
    LOGI("✓✓✓ Can safely call original functions from hooks");
    LOGI("Symbols resolved: %s", hooks_installed ? "YES" : "NO");
    LOGI("Ready for bypass/spray mode control");
    
    return JNI_TRUE;
}

/**
 * Enable state bypass mode
 * Sets global flag that will be checked by Java-layer hooks
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_enableBypass(JNIEnv *env, jclass clazz) {
    bypass_enabled = true;
    LOGI("Bypass mode ENABLED (Java hooks will check this flag)");
}

/**
 * Disable state bypass mode
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_disableBypass(JNIEnv *env, jclass clazz) {
    bypass_enabled = false;
    LOGI("Bypass mode DISABLED");
}

/**
 * Enable spray mode for continuous SENSF_REQ response
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_enableSprayMode(JNIEnv *env, jclass clazz) {
    spray_mode_enabled = true;
    bypass_enabled = true;  // Spray mode requires bypass
    LOGI("Spray mode ENABLED (continuous SENSF_RES transmission)");
}

/**
 * Disable spray mode
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_disableSprayMode(JNIEnv *env, jclass clazz) {
    spray_mode_enabled = false;
    LOGI("Spray mode DISABLED");
}

/**
 * Check if bypass mode is enabled (can be called from Java hooks)
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isBypassEnabled(JNIEnv *env, jclass clazz) {
    return bypass_enabled ? JNI_TRUE : JNI_FALSE;
}

/**
 * Check if spray mode is enabled
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isSprayModeEnabled(JNIEnv *env, jclass clazz) {
    return spray_mode_enabled ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get hook status
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_isInstalled(JNIEnv *env, jclass clazz) {
    return hooks_installed ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get status information
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_getStatus(JNIEnv *env, jclass clazz) {
    char info[1024];
    snprintf(info, sizeof(info),
             "Native Hooks Status:\n"
             "  Dobby Version: %s\n"
             "  Installed: %s\n"
             "  Bypass Enabled: %s\n"
             "  Spray Mode: %s\n"
             "  libnfc-nci.so: %p\n"
             "  libnfc_nci_jni.so: %p\n"
             "  nfa_dm_is_data_exchange_allowed: %p\n"
             "  nfa_dm_act_send_raw_frame: %p\n"
             "  NFC_SendData: %p\n"
             "  Process ID: %d\n"
             "  Hook Framework: Dobby (Professional)",
             DobbyGetVersion(),
             hooks_installed ? "YES" : "NO",
             bypass_enabled ? "YES" : "NO",
             spray_mode_enabled ? "YES" : "NO",
             libnfc_handle,
             libnfc_jni_handle,
             orig_nfa_dm_is_data_exchange_allowed,
             orig_nfa_dm_act_send_raw_frame,
             orig_NFC_SendData,
             getpid());
    
    return env->NewStringUTF(info);
}

} // extern "C"
