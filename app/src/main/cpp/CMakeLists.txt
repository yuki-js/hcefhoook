cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library for NFC stack manipulation
# This library provides Dobby hooking functionality for bypassing NFA state machine
# checks in Observe Mode
#
# DOBBY LIBRARY INTEGRATION:
# ==========================
# Built from https://github.com/jmpews/Dobby (Apache License 2.0)
# - libdobby.so: Prebuilt for arm64-v8a (located in jniLibs)
# - Provides DobbyHook, DobbySymbolResolver, and other hooking APIs
# - Direct nfa_dm_cb manipulation for state bypass
# - Support for libstnfc_nci_jni.so (real device) and libnfc_nci_jni.so (AOSP)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include Dobby header directory
include_directories(dobby/include)

# Import prebuilt Dobby library
add_library(dobby SHARED IMPORTED)
set_target_properties(dobby PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libdobby.so)

add_library(${PROJECT_NAME} SHARED
        dobby_hooks.cpp
        dobby_impl.cpp)  # Wrapper around Dobby functionality

target_link_libraries(${PROJECT_NAME}
        dobby
        android
        log
        dl)
