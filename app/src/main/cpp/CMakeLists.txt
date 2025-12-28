cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# For now, build without Dobby due to Android NDK compatibility issues
# We'll use dlsym-based hooking or include prebuilt Dobby libraries later

# Native hooking library 
add_library(${PROJECT_NAME} SHARED
        native_hook.cpp
        dobby_hooks.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log
        dl)

# TODO: Add prebuilt Dobby library or use alternative hooking method
# Users can manually add libdobby.a to jniLibs/
