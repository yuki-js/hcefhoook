cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library for NFC stack manipulation
# This library provides symbol resolution and state management hooks
# for bypassing NFA state machine checks in Observe Mode
#
# NOW USING: Dobby library for professional inline hooking

# Configure Dobby options BEFORE adding it as subdirectory
# Disable ASM trampoline which has Android NDK compatibility issues
set(BUILD_WITH_TRAMPOLINE_ASM OFF CACHE BOOL "Disable ASM trampoline for Android NDK compatibility" FORCE)
set(Plugin.SymbolResolver ON CACHE BOOL "Enable symbol resolver plugin" FORCE)

# Add Dobby as a subdirectory
add_subdirectory(dobby/Dobby-master EXCLUDE_FROM_ALL)

# Include Dobby headers
include_directories(dobby/Dobby-master/include)

add_library(${PROJECT_NAME} SHARED
        dobby_hooks.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log
        dl
        dobby)  # Link against Dobby library
