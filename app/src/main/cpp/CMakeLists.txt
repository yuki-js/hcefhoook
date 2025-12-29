cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native utility library for HCE-F Hook
# 
# NOTE: Dobby has been removed in favor of Frida for native hooking.
# This library now provides only utility functions.
# 
# For actual native hooking, use the Frida script at:
#   assets/frida/observe_mode_bypass.js
# Run: frida -U -f com.android.nfc -l observe_mode_bypass.js --no-pause
#
# Key Hook Targets (from AOSP analysis):
# - NFA_SendRawFrame @ 0x147100
# - nfa_dm_act_send_raw_frame @ 0x14e070 (KEY BLOCKING POINT)
# - nfa_dm_cb @ 0x24c0f8 (state variable)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Simple utility library (no Dobby)
add_library(${PROJECT_NAME} SHARED
        native_utils.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log)
