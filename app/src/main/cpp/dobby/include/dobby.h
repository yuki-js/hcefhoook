/**
 * Dobby Hook Framework - Header-Only Declarations
 * 
 * This is a minimal header file with Dobby API declarations.
 * For full Dobby functionality, you need to:
 * 1. Download prebuilt Dobby library for Android
 * 2. Place libdobby.so in app/src/main/jniLibs/arm64-v8a/
 * 3. OR build Dobby from source using a compatible version
 * 
 * Recommended sources:
 * - https://github.com/jmpews/Dobby (original, may have Android NDK issues)
 * - https://github.com/Rprop/Dobby (Android-compatible fork)
 * - Prebuilt: https://github.com/jmpews/Dobby/releases
 * 
 * For this PoC, we provide stub implementations that demonstrate
 * the correct API usage pattern.
 */

#ifndef DOBBY_H
#define DOBBY_H

#include <stdint.h>  // Required for uintptr_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Install hook at target address
 * 
 * @param address - Target function address to hook
 * @param fake_func - Replacement function
 * @param out_origin_func - Pointer to receive trampoline to original function
 * @return 0 on success, non-zero on failure
 */
int DobbyHook(void *address, void *fake_func, void **out_origin_func);

/**
 * Remove hook and restore original function
 * 
 * @param address - Address of hooked function
 * @return 0 on success, non-zero on failure
 */
int DobbyDestroy(void *address);

/**
 * Get Dobby library version
 * 
 * @return Version string
 */
const char *DobbyGetVersion();

/**
 * DobbySymbolResolver - Advanced symbol resolution
 * 
 * Resolves symbols from loaded modules using:
 * - ELF parsing
 * - /proc/self/maps enumeration
 * - Symbol table analysis
 * - Fallback to dlsym
 * 
 * @param module_name - Name of the module (e.g., "libnfc_nci_jni.so")
 * @param symbol_name - Symbol to resolve
 * @return Address of symbol, or NULL if not found
 */
void *DobbySymbolResolver(const char *module_name, const char *symbol_name);

/**
 * Get base address of a loaded module
 * 
 * @param module_name - Name of the module
 * @return Base address, or 0 if not found
 */
uintptr_t DobbyGetModuleBase(const char *module_name);

/**
 * List all installed hooks (for debugging)
 */
void DobbyListHooks();

#ifdef __cplusplus
}
#endif

#endif // DOBBY_H
