/**
 * HCE-F Hook - Native Utilities
 * 
 * This module provides utility functions for the HCE-F Hook project.
 * 
 * NOTE: Dobby has been removed in favor of Frida for actual native hooking.
 * For hooking functionality, use the Frida script at:
 *   assets/frida/observe_mode_bypass.js
 * 
 * This native library now only provides:
 * - Module enumeration utilities
 * - Memory information helpers
 * - JNI wrapper for Frida coordination
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define TAG "HcefHook.NativeUtils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ============================================================================
// Module Information
// ============================================================================

/**
 * Check if a module is loaded by name
 */
static bool is_module_loaded(const char* module_name) {
    if (!module_name) return false;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    
    char line[1024];
    bool found = false;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            found = true;
            break;
        }
    }
    
    fclose(fp);
    return found;
}

/**
 * Get base address of a loaded module
 */
static uintptr_t get_module_base(const char* module_name) {
    if (!module_name) return 0;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    
    char line[1024];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    
    fclose(fp);
    return base;
}

// ============================================================================
// JNI Interface
// ============================================================================

extern "C" {

/**
 * Check if NFC library is loaded
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_isNfcLibraryLoaded(JNIEnv *env, jclass clazz) {
    const char* libs[] = {
        "libstnfc_nci_jni.so",
        "libnfc_nci_jni.so",
        "libnfc-nci.so",
        nullptr
    };
    
    for (int i = 0; libs[i] != nullptr; i++) {
        if (is_module_loaded(libs[i])) {
            LOGI("Found NFC library: %s", libs[i]);
            return JNI_TRUE;
        }
    }
    
    LOGW("No NFC library found in process");
    return JNI_FALSE;
}

/**
 * Get NFC library name if loaded
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getNfcLibraryName(JNIEnv *env, jclass clazz) {
    const char* libs[] = {
        "libstnfc_nci_jni.so",
        "libnfc_nci_jni.so",
        "libnfc-nci.so",
        nullptr
    };
    
    for (int i = 0; libs[i] != nullptr; i++) {
        if (is_module_loaded(libs[i])) {
            return env->NewStringUTF(libs[i]);
        }
    }
    
    return env->NewStringUTF("(not found)");
}

/**
 * Get NFC library base address
 */
JNIEXPORT jlong JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getNfcLibraryBase(JNIEnv *env, jclass clazz) {
    const char* libs[] = {
        "libstnfc_nci_jni.so",
        "libnfc_nci_jni.so",
        "libnfc-nci.so",
        nullptr
    };
    
    for (int i = 0; libs[i] != nullptr; i++) {
        uintptr_t base = get_module_base(libs[i]);
        if (base != 0) {
            LOGI("NFC library base: 0x%lx", base);
            return (jlong)base;
        }
    }
    
    return 0;
}

/**
 * Get current process ID
 */
JNIEXPORT jint JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getProcessId(JNIEnv *env, jclass clazz) {
    return (jint)getpid();
}

/**
 * Log process maps for debugging
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_logProcessMaps(JNIEnv *env, jclass clazz) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Cannot open /proc/self/maps");
        return;
    }
    
    LOGI("=== Process Maps (NFC related) ===");
    
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // Log only NFC-related entries
        if (strstr(line, "nfc") || strstr(line, "NFC") || strstr(line, "stnfc")) {
            // Remove newline
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len-1] = '\0';
            }
            LOGI("%s", line);
        }
    }
    
    fclose(fp);
    LOGI("=== End Process Maps ===");
}

} // extern "C"
