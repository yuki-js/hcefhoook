cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library for NFC stack manipulation
# This library provides symbol resolution and state management hooks
# for bypassing NFA state machine checks in Observe Mode
#
# NOTE: Full inline hooking (Dobby) requires prebuilt libraries
# Current implementation uses dlsym-based symbol resolution

add_library(${PROJECT_NAME} SHARED
        dobby_hooks.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log
        dl)

# TODO: Add prebuilt Dobby library for true inline hooking
# Users can manually add libdobby.a to jniLibs/ for enhanced functionality
