/**
 * Dobby Hook Framework - Stub Implementation
 * 
 * This provides STUB implementations of Dobby functions for compilation.
 * These stubs demonstrate the correct usage pattern but don't provide
 * actual hooking functionality.
 * 
 * TO ENABLE REAL DOBBY HOOKS:
 * ============================
 * 1. Download prebuilt libdobby.so OR build from source
 * 2. Place in app/src/main/jniLibs/arm64-v8a/libdobby.so
 * 3. Remove this dobby_stub.cpp file
 * 4. Update CMakeLists.txt to link against libdobby.so
 * 
 * For now, this allows the code to compile and demonstrates
 * the correct API usage that will work with real Dobby.
 */

#include "dobby.h"
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>

#define TAG "Dobby.Stub"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/**
 * Stub implementation of DobbyHook
 * 
 * In real Dobby:
 * - Creates a trampoline with original function instructions
 * - Patches target function to jump to fake_func
 * - Returns pointer to trampoline in out_origin_func
 * 
 * This stub:
 * - Just saves the original address
 * - Logs a warning that real hooking is not active
 * - Returns success so code can continue
 */
extern "C" int DobbyHook(void *address, void *fake_func, void **out_origin_func) {
    LOGW("╔════════════════════════════════════════╗");
    LOGW("║   DOBBY STUB - NOT REAL HOOKING!      ║");
    LOGW("╠════════════════════════════════════════╣");
    LOGW("║ Target:     %p                         ║", address);
    LOGW("║ Hook:       %p                         ║", fake_func);
    LOGW("║                                        ║");
    LOGW("║ To enable real Dobby hooks:            ║");
    LOGW("║ 1. Get libdobby.so (prebuilt/build)    ║");
    LOGW("║ 2. Place in jniLibs/arm64-v8a/         ║");
    LOGW("║ 3. Remove dobby_stub.cpp               ║");
    LOGW("╚════════════════════════════════════════╝");
    
    // For stub: Just save the original address
    // Real Dobby would create a proper trampoline
    if (out_origin_func) {
        *out_origin_func = address;
    }
    
    // Return "success" to allow code to continue
    // In real usage, this would actually install the hook
    return 0;
}

/**
 * Stub implementation of DobbySymbolResolver
 */
extern "C" void *DobbySymbolResolver(const char *image_name, const char *symbol_name) {
    void *handle = RTLD_DEFAULT;
    bool handle_from_load = false;

    if (image_name && strlen(image_name) > 0) {
        handle = dlopen(image_name, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) {
            LOGW("DobbySymbolResolver stub: %s not preloaded, trying RTLD_NOW", image_name);
            handle = dlopen(image_name, RTLD_NOW);
            handle_from_load = handle != nullptr;
        }
        if (!handle) {
            LOGW("DobbySymbolResolver stub: dlopen(%s) failed: %s", image_name, dlerror());
            handle = RTLD_DEFAULT;
        }
    }

    void *symbol = dlsym(handle, symbol_name);
    if (!symbol) {
        LOGW("DobbySymbolResolver stub: symbol %s not found: %s", symbol_name, dlerror());
    } else {
        LOGI("DobbySymbolResolver stub: resolved %s -> %p", symbol_name, symbol);
    }

    if (handle_from_load && handle && handle != RTLD_DEFAULT && handle != RTLD_NEXT) {
        dlclose(handle);
    }
    return symbol;
}

/**
 * Stub implementation of DobbyDestroy
 */
extern "C" int DobbyDestroy(void *address) {
    LOGW("DobbyDestroy called (stub): %p", address);
    return 0;
}

/**
 * Stub implementation of DobbyGetVersion
 */
extern "C" const char *DobbyGetVersion() {
    return "STUB-v1.0 (Replace with real Dobby library)";
}
