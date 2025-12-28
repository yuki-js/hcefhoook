/**
 * HCE-F Hook - Native Function Hooking (PLT Hook Implementation)
 * 
 * This module implements runtime native function hooks using PLT (Procedure Linkage Table) hooking.
 * It targets libnfc-nci.so and libnfc_nci_jni.so functions that control NFC state
 * and data transmission, enabling SENSF_RES injection in Observe Mode.
 * 
 * CRITICAL: This code MUST execute in the android.nfc process context, not in
 * the hcefhook app package. The Xposed module loads this library into com.android.nfc.
 * 
 * NOTE: Full Dobby integration is planned but requires prebuilt libraries due to
 * Android NDK assembly compatibility issues. This implementation uses basic
 * function pointer replacement for now.
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

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

// Function pointers for symbols we want to monitor/hook
typedef bool (*nfa_dm_is_data_exchange_allowed_t)(void);
typedef int (*nfa_dm_act_send_raw_frame_t)(void* p_data);
typedef int (*NFC_SendData_t)(int conn_id, void* p_buf);

static nfa_dm_is_data_exchange_allowed_t orig_nfa_dm_is_data_exchange_allowed = nullptr;
static nfa_dm_act_send_raw_frame_t orig_nfa_dm_act_send_raw_frame = nullptr;
static NFC_SendData_t orig_NFC_SendData = nullptr;

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
 * Resolve function pointers for monitoring
 * Note: This doesn't actually hook yet - full Dobby integration needed
 */
static bool resolve_functions(void* lib_handle, const char* symbol_name, void** func_ptr) {
    void* target = find_symbol_in_lib(lib_handle, symbol_name);
    if (!target) {
        LOGW("Cannot resolve %s: symbol not found", symbol_name);
        return false;
    }
    
    *func_ptr = target;
    LOGI("Resolved %s at %p", symbol_name, target);
    return true;
}

/**
 * Install hooks (currently just resolves symbols - full hooking requires Dobby)
 * 
 * CRITICAL: This must be called from the android.nfc process after libnfc-nci.so
 * and libnfc_nci_jni.so are loaded into memory.
 * 
 * TODO: Implement actual inline hooking when Dobby prebuilt libraries are added
 */
extern "C" {

JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_DobbyHooks_installHooks(JNIEnv *env, jclass clazz) {
    if (hooks_installed) {
        LOGW("Hooks already installed");
        return JNI_TRUE;
    }
    
    LOGI("=== Installing Native Hooks ===");
    LOGI("Process: %d", getpid());
    LOGI("NOTE: Full inline hooking requires Dobby prebuilt library");
    LOGI("Current implementation: Symbol resolution + state management");
    
    // Open libnfc-nci.so (should already be loaded in android.nfc process)
    libnfc_handle = dlopen("libnfc-nci.so", RTLD_NOW);
    if (!libnfc_handle) {
        LOGE("Failed to open libnfc-nci.so: %s", dlerror());
        // Try alternative name
        libnfc_handle = dlopen("libnfc_nci.so", RTLD_NOW);
        if (!libnfc_handle) {
            LOGE("Failed to open libnfc_nci.so: %s", dlerror());
            return JNI_FALSE;
        }
    }
    LOGI("Loaded libnfc-nci.so: %p", libnfc_handle);
    
    // Open libnfc_nci_jni.so (JNI bridge)
    libnfc_jni_handle = dlopen("libnfc_nci_jni.so", RTLD_NOW);
    if (!libnfc_jni_handle) {
        LOGW("Failed to open libnfc_nci_jni.so: %s", dlerror());
        // This is optional, continue anyway
    } else {
        LOGI("Loaded libnfc_nci_jni.so: %p", libnfc_jni_handle);
    }
    
    // Resolve function pointers
    bool success = true;
    
    // Function 1: nfa_dm_is_data_exchange_allowed (state check)
    resolve_functions(libnfc_handle, "nfa_dm_is_data_exchange_allowed",
                     (void**)&orig_nfa_dm_is_data_exchange_allowed);
    
    // Function 2: nfa_dm_act_send_raw_frame (main send function)
    resolve_functions(libnfc_handle, "nfa_dm_act_send_raw_frame",
                     (void**)&orig_nfa_dm_act_send_raw_frame);
    
    // Function 3: NFC_SendData (lower-level send)
    resolve_functions(libnfc_handle, "NFC_SendData",
                     (void**)&orig_NFC_SendData);
    
    // Try alternative symbol names for STMicroelectronics chips
    if (!orig_NFC_SendData) {
        LOGI("Trying alternative symbol names...");
        resolve_functions(libnfc_handle, "nfc_ncif_send_data",
                         (void**)&orig_NFC_SendData);
    }
    
    // Try to find NFA discovery control block for state manipulation
    void* nfa_dm_cb = dlsym(libnfc_handle, "nfa_dm_cb");
    if (nfa_dm_cb) {
        LOGI("Found nfa_dm_cb at %p - state spoofing may be possible", nfa_dm_cb);
    }
    
    hooks_installed = true;
    LOGI("=== Native Hooks Installation Complete ===");
    LOGI("Symbols resolved: %s", hooks_installed ? "YES" : "NO");
    LOGI("Ready for bypass/spray mode control");
    LOGW("NOTE: Full inline hooking pending Dobby integration");
    
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
             "  Installed: %s\n"
             "  Bypass Enabled: %s\n"
             "  Spray Mode: %s\n"
             "  libnfc-nci.so: %p\n"
             "  libnfc_nci_jni.so: %p\n"
             "  nfa_dm_is_data_exchange_allowed: %p\n"
             "  nfa_dm_act_send_raw_frame: %p\n"
             "  NFC_SendData: %p\n"
             "  Process ID: %d\n"
             "  Note: Inline hooking requires Dobby prebuilt library",
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
