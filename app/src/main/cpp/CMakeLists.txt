cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library for NFC stack manipulation
# This library provides symbol resolution and state management hooks
# for bypassing NFA state machine checks in Observe Mode
#
# DOBBY INTEGRATION:
# ==================
# Currently using stub implementation for compilation.
# To enable real Dobby hooks:
# 1. Get libdobby.so (prebuilt from releases OR build from source)
# 2. Place in app/src/main/jniLibs/arm64-v8a/libdobby.so
# 3. Remove dobby_stub.cpp from add_library() below
# 4. Add: find_library(dobby-lib dobby)
# 5. Link: target_link_libraries(${PROJECT_NAME} ${dobby-lib})

# Include Dobby header directory
include_directories(dobby/include)

add_library(${PROJECT_NAME} SHARED
        dobby_hooks.cpp
        dobby_stub.cpp)  # Remove this line when using real Dobby

target_link_libraries(${PROJECT_NAME}
        android
        log
        dl)
        # Add dobby here when using real library
