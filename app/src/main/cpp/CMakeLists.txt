cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native library for HCE-F Hook
# 
# NOTE: Dobby has been removed in favor of Frida for hooking.
# This library now provides only utility functions.
# For actual native hooking, use the Frida script at:
#   assets/frida/observe_mode_bypass.js
#
# Run with: frida -U -f com.android.nfc -l observe_mode_bypass.js

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Simple utility library (no Dobby)
add_library(${PROJECT_NAME} SHARED
        native_utils.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log)
