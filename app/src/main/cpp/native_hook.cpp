/**
 * HCE-F Hook - Native Hooking Module
 * 
 * This module provides native layer hooking capabilities for the NFC stack.
 * It can be used standalone or in conjunction with Frida for more advanced hooking.
 * 
 * Key targets:
 * - nfa_dm_act_send_raw_frame() - The main function that checks state before sending
 * - nfa_dm_cb.disc_cb.disc_state - The state variable to spoof
 * - NFC_SendData() - Lower level send function
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

#define TAG "HcefHook.Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// NFA Discovery states (from nfa_dm_int.h)
#define NFA_DM_RFST_IDLE            0x00
#define NFA_DM_RFST_DISCOVERY       0x01
#define NFA_DM_RFST_W4_ALL_DISC     0x02
#define NFA_DM_RFST_W4_HOST_SELECT  0x03
#define NFA_DM_RFST_POLL_ACTIVE     0x04
#define NFA_DM_RFST_LISTEN_ACTIVE   0x05
#define NFA_DM_RFST_LISTEN_SLEEP    0x06

// SENSF command codes
#define SENSF_REQ_CMD 0x00
#define SENSF_RES_CMD 0x01

// Global state
static void* libnfc_handle = nullptr;
static uint8_t* nfa_dm_cb_ptr = nullptr;
static int disc_state_offset = -1;
static bool bypass_enabled = false;

// Symbol addresses (to be resolved)
static void* nfa_send_raw_frame_addr = nullptr;
static void* nfc_send_data_addr = nullptr;

/**
 * Find libnfc-nci.so in memory
 */
static void* find_libnfc() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    
    char line[512];
    void* base = nullptr;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libnfc-nci.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", (unsigned long*)&base);
            break;
        }
    }
    
    fclose(fp);
    return base;
}

/**
 * Find a symbol in the library
 */
static void* find_symbol(const char* name) {
    if (!libnfc_handle) {
        libnfc_handle = dlopen("libnfc-nci.so", RTLD_NOW);
        if (!libnfc_handle) {
            LOGE("Failed to open libnfc-nci.so: %s", dlerror());
            return nullptr;
        }
    }
    
    void* addr = dlsym(libnfc_handle, name);
    if (addr) {
        LOGI("Found %s at %p", name, addr);
    } else {
        LOGD("Symbol %s not found", name);
    }
    return addr;
}

#ifdef USE_DOBBY
extern "C" int DobbyHook(void* function_address, void* replace_call, void** orig_func);

static int (*orig_hal_send_downstream)(void* ctx, const uint8_t* data, size_t len) = nullptr;

static int hooked_hal_send_downstream(void* ctx, const uint8_t* data, size_t len) {
    LOGI("[Dobby] HalSendDownstream len=%zu", len);
    if (bypass_enabled) {
        LOGI("[Dobby] bypass_enabled=true (pass-through)");
    }
    if (orig_hal_send_downstream) {
        return orig_hal_send_downstream(ctx, data, len);
    }
    return -1;
}

static void install_dobby_hooks() {
    void* hal_send = dlsym(libnfc_handle, "_Z17HalSendDownstreamPvPKhm");
    if (hal_send && DobbyHook(hal_send, (void*)hooked_hal_send_downstream,
                              (void**)&orig_hal_send_downstream) == 0) {
        LOGI("Dobby hooked HalSendDownstream @ %p", hal_send);
    } else {
        LOGD("Dobby hook skipped (symbol or engine unavailable)");
    }
}
#endif

/**
 * Search for nfa_dm_cb global variable
 * This is a heuristic search based on code patterns
 */
static uint8_t* find_nfa_dm_cb() {
    // First try to find it via dlsym
    uint8_t* cb = (uint8_t*)find_symbol("nfa_dm_cb");
    if (cb) return cb;
    
    // If not exported, we need to search for it
    // This requires pattern matching which is device-specific
    LOGD("nfa_dm_cb not exported, requires memory scanning");
    return nullptr;
}

extern "C" {

/**
 * Initialize native hooks
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_init(JNIEnv *env, jclass clazz) {
    LOGI("Initializing native hooks...");
    
    void* base = find_libnfc();
    if (!base) {
        LOGE("libnfc-nci.so not found in memory");
        return JNI_FALSE;
    }
    LOGI("libnfc-nci.so base: %p", base);
    
    // Try to find key symbols
    nfa_send_raw_frame_addr = find_symbol("NFA_SendRawFrame");
    nfc_send_data_addr = find_symbol("NFC_SendData");
    nfa_dm_cb_ptr = find_nfa_dm_cb();
    
#ifdef USE_DOBBY
    install_dobby_hooks();
#endif

    if (nfa_dm_cb_ptr) {
        LOGI("nfa_dm_cb found at %p", nfa_dm_cb_ptr);
    }
    
    return JNI_TRUE;
}

/**
 * Enable state bypass for data transmission
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_enableBypass(JNIEnv *env, jclass clazz) {
    bypass_enabled = true;
    LOGI("State bypass enabled");
}

/**
 * Disable state bypass
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_disableBypass(JNIEnv *env, jclass clazz) {
    bypass_enabled = false;
    LOGI("State bypass disabled");
}

/**
 * Get current discovery state
 */
JNIEXPORT jint JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_getDiscState(JNIEnv *env, jclass clazz) {
    if (!nfa_dm_cb_ptr || disc_state_offset < 0) {
        return -1;
    }
    return *(nfa_dm_cb_ptr + disc_state_offset);
}

/**
 * Spoof discovery state to LISTEN_ACTIVE
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_spoofState(JNIEnv *env, jclass clazz, jint state) {
    if (!nfa_dm_cb_ptr || disc_state_offset < 0) {
        LOGE("Cannot spoof state: nfa_dm_cb not found");
        return JNI_FALSE;
    }
    
    uint8_t old_state = *(nfa_dm_cb_ptr + disc_state_offset);
    *(nfa_dm_cb_ptr + disc_state_offset) = (uint8_t)state;
    LOGI("State spoofed: 0x%02x -> 0x%02x", old_state, state);
    
    return JNI_TRUE;
}

/**
 * Build SENSF_RES frame
 */
JNIEXPORT jbyteArray JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_buildSensfRes(
        JNIEnv *env, jclass clazz, jbyteArray idm, jbyteArray pmm) {
    
    jbyte* idm_data = env->GetByteArrayElements(idm, nullptr);
    jbyte* pmm_data = env->GetByteArrayElements(pmm, nullptr);
    
    // SENSF_RES: [Length][0x01][IDm 8B][PMm 8B]
    uint8_t frame[18];
    frame[0] = 18;  // Length
    frame[1] = SENSF_RES_CMD;
    memcpy(&frame[2], idm_data, 8);
    memcpy(&frame[10], pmm_data, 8);
    
    env->ReleaseByteArrayElements(idm, idm_data, 0);
    env->ReleaseByteArrayElements(pmm, pmm_data, 0);
    
    jbyteArray result = env->NewByteArray(18);
    env->SetByteArrayRegion(result, 0, 18, (jbyte*)frame);
    
    LOGI("Built SENSF_RES frame (18 bytes)");
    return result;
}

/**
 * Get library info for debugging
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_getInfo(JNIEnv *env, jclass clazz) {
    char info[512];
    snprintf(info, sizeof(info),
             "libnfc base: %p\n"
             "NFA_SendRawFrame: %p\n"
             "NFC_SendData: %p\n"
             "nfa_dm_cb: %p\n"
             "bypass_enabled: %s",
             find_libnfc(),
             nfa_send_raw_frame_addr,
             nfc_send_data_addr,
             nfa_dm_cb_ptr,
             bypass_enabled ? "true" : "false");
    
    return env->NewStringUTF(info);
}

/**
 * Set the disc_state offset in nfa_dm_cb
 * This needs to be calibrated per device/Android version
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_native_NativeHook_setDiscStateOffset(JNIEnv *env, jclass clazz, jint offset) {
    disc_state_offset = offset;
    LOGI("disc_state offset set to %d", offset);
}

} // extern "C"
