/**
 * HCE-F Hook - Native Utilities
 * 
 * This module provides utility functions for the HCE-F Hook project.
 * 
 * NOTE: Dobby has been removed in favor of Frida for native hooking.
 * For hooking functionality, use the Frida script at:
 *   assets/frida/observe_mode_bypass.js
 * 
 * This library provides:
 * - Process and module information utilities
 * - Memory inspection helpers
 * - JNI coordination functions
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define TAG "HcefHook.Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// NFC library names to search for
static const char* NFC_LIBS[] = {
    "libstnfc_nci_jni.so",    // ST NFC chipset (Pixel devices)
    "libnfc_nci_jni.so",      // Standard AOSP
    "libnfc-nci.so",          // Alternative
    nullptr
};

/**
 * Check if a library is loaded in current process
 */
static bool isLibraryLoaded(const char* libName) {
    if (!libName) return false;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    
    char line[1024];
    bool found = false;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libName)) {
            found = true;
            break;
        }
    }
    
    fclose(fp);
    return found;
}

/**
 * Get base address of a loaded library
 */
static uintptr_t getLibraryBase(const char* libName) {
    if (!libName) return 0;
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    
    char line[1024];
    uintptr_t base = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libName)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    
    fclose(fp);
    return base;
}

extern "C" {

/**
 * JNI_OnLoad - Called when native library is loaded
 */
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("=== HCE-F Hook Native Library Loaded ===");
    LOGI("Implementation: Utility functions only (Frida handles hooking)");
    LOGI("Process ID: %d", getpid());
    
    // Check for NFC libraries
    for (int i = 0; NFC_LIBS[i] != nullptr; i++) {
        if (isLibraryLoaded(NFC_LIBS[i])) {
            uintptr_t base = getLibraryBase(NFC_LIBS[i]);
            LOGI("Found NFC library: %s @ 0x%lx", NFC_LIBS[i], base);
        }
    }
    
    LOGI("For native hooking, use: frida -U -f com.android.nfc -l observe_mode_bypass.js");
    
    return JNI_VERSION_1_6;
}

/**
 * Check if any NFC library is loaded
 */
JNIEXPORT jboolean JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_isNfcLibraryLoaded(JNIEnv* env, jclass clazz) {
    for (int i = 0; NFC_LIBS[i] != nullptr; i++) {
        if (isLibraryLoaded(NFC_LIBS[i])) {
            LOGI("NFC library found: %s", NFC_LIBS[i]);
            return JNI_TRUE;
        }
    }
    
    LOGW("No NFC library found in process");
    return JNI_FALSE;
}

/**
 * Get name of the loaded NFC library
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getNfcLibraryName(JNIEnv* env, jclass clazz) {
    for (int i = 0; NFC_LIBS[i] != nullptr; i++) {
        if (isLibraryLoaded(NFC_LIBS[i])) {
            return env->NewStringUTF(NFC_LIBS[i]);
        }
    }
    return env->NewStringUTF("(not found)");
}

/**
 * Get base address of NFC library
 */
JNIEXPORT jlong JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getNfcLibraryBase(JNIEnv* env, jclass clazz) {
    for (int i = 0; NFC_LIBS[i] != nullptr; i++) {
        uintptr_t base = getLibraryBase(NFC_LIBS[i]);
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
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getProcessId(JNIEnv* env, jclass clazz) {
    return (jint)getpid();
}

/**
 * Log NFC-related process maps for debugging
 */
JNIEXPORT void JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_logProcessMaps(JNIEnv* env, jclass clazz) {
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
            // Remove trailing newline
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

/**
 * Get status information
 */
JNIEXPORT jstring JNICALL
Java_app_aoki_yuki_hcefhook_nativehook_NativeUtils_getStatus(JNIEnv* env, jclass clazz) {
    char status[2048];
    
    snprintf(status, sizeof(status),
        "=== HCE-F Hook Native Status ===\n"
        "Implementation: Frida-based (Dobby removed)\n"
        "Process ID: %d\n"
        "\n"
        "=== Hook Targets ===\n"
        "NFA_SendRawFrame: 0x147100\n"
        "nfa_dm_act_send_raw_frame: 0x14e070\n"
        "nfa_dm_cb: 0x24c0f8\n"
        "\n"
        "=== Frida Usage ===\n"
        "Script: assets/frida/observe_mode_bypass.js\n"
        "Run: frida -U -f com.android.nfc -l observe_mode_bypass.js\n",
        getpid());
    
    return env->NewStringUTF(status);
}

} // extern "C"
