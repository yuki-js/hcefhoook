/**
 * Dobby Helper Functions
 * 
 * This file provides helper utilities that extend the actual Dobby library (libdobby.so).
 * The real Dobby library already provides core functionality:
 * - DobbyHook
 * - DobbyDestroy  
 * - DobbySymbolResolver
 * - DobbyGetVersion
 * 
 * This file adds convenience helpers:
 * - DobbyListHooks: List installed hooks for debugging
 * - DobbyGetModuleBase: Find base address of loaded modules
 * - Module enumeration via /proc/self/maps
 */

#include "dobby.h"
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <string>

#define TAG "Dobby.Helpers"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ============================================================================
// Module Information
// ============================================================================

struct ModuleInfo {
    std::string name;
    std::string path;
    uintptr_t base_address;
    uintptr_t end_address;
};

/**
 * Enumerate loaded modules by parsing /proc/self/maps
 */
static std::vector<ModuleInfo> enumerate_loaded_modules() {
    std::vector<ModuleInfo> modules;
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return modules;
    }
    
    char line[1024];
    ModuleInfo current_module;
    bool in_module = false;
    
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        char perms[5];
        char path[512] = {0};
        
        // Parse: address perms offset dev inode pathname
        int matches = sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %511s",
                            &start, &end, perms, path);
        
        if (matches >= 3 && strlen(path) > 0 && path[0] == '/') {
            // Check if this is a new module or continuation
            if (!in_module || current_module.path != path) {
                // Save previous module if exists
                if (in_module) {
                    modules.push_back(current_module);
                }
                
                // Start new module
                current_module.path = path;
                current_module.base_address = start;
                current_module.end_address = end;
                
                // Extract module name from path
                const char* name_start = strrchr(path, '/');
                current_module.name = name_start ? (name_start + 1) : path;
                
                in_module = true;
            } else {
                // Extend current module's end address
                current_module.end_address = end;
            }
        }
    }
    
    // Add last module
    if (in_module) {
        modules.push_back(current_module);
    }
    
    fclose(fp);
    return modules;
}

// ============================================================================
// Dobby Helper Functions
// ============================================================================

/**
 * Hook tracking for DobbyListHooks
 * Note: We don't actually manage hooks - real Dobby does that
 * This is just for debugging/logging purposes
 */
struct HookRecord {
    void* target;
    void* replacement;
    std::string target_name;
};

static std::map<void*, HookRecord> g_hook_records;

/**
 * Track a hook installation (call this after DobbyHook succeeds)
 */
void track_dobby_hook(void* target, void* replacement, const char* name) {
    HookRecord record;
    record.target = target;
    record.replacement = replacement;
    record.target_name = name ? name : "unknown";
    g_hook_records[target] = record;
}

/**
 * List all tracked hooks (debugging utility)
 */
extern "C" void DobbyListHooks() {
    LOGI("═══════════════════════════════════════");
    LOGI("  TRACKED DOBBY HOOKS: %zu", g_hook_records.size());
    LOGI("═══════════════════════════════════════");
    
    if (g_hook_records.empty()) {
        LOGI("  (no hooks tracked)");
    } else {
        for (const auto& pair : g_hook_records) {
            LOGI("  %s:", pair.second.target_name.c_str());
            LOGI("    Target:      %p", pair.second.target);
            LOGI("    Replacement: %p", pair.second.replacement);
        }
    }
    LOGI("═══════════════════════════════════════");
}

/**
 * Get module base address
 */
extern "C" uintptr_t DobbyGetModuleBase(const char* module_name) {
    if (!module_name) {
        return 0;
    }
    
    auto modules = enumerate_loaded_modules();
    for (const auto& mod : modules) {
        if (mod.name.find(module_name) != std::string::npos) {
            LOGI("Found module '%s' at 0x%lx", module_name, mod.base_address);
            return mod.base_address;
        }
    }
    
    LOGW("Module '%s' not found", module_name);
    return 0;
}
