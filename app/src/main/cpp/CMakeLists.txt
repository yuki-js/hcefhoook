cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library for NFC stack manipulation
# This library provides Dobby-style symbol resolution and state management hooks
# for bypassing NFA state machine checks in Observe Mode
#
# DOBBY IMPLEMENTATION:
# ==================
# This implementation uses Dobby concepts without requiring the full library:
# - DobbySymbolResolver: Advanced symbol resolution via ELF parsing
# - DobbyHook API: Hook management and tracking
# - Direct nfa_dm_cb manipulation: State bypass without inline patching
# - Support for libstnfc_nci_jni.so (real device) and libnfc_nci_jni.so (AOSP)

# C++ Standard (required for Dobby-style implementation)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include Dobby header directory
include_directories(dobby/include)

add_library(${PROJECT_NAME} SHARED
        dobby_hooks.cpp
        dobby_impl.cpp)  # Dobby-style implementation with DobbySymbolResolver

target_link_libraries(${PROJECT_NAME}
        android
        log
        dl)
