cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library using inline hooking
add_library(${PROJECT_NAME} SHARED
        native_hook.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log)

# Download Frida Gadget at build time (optional - for full Frida support)
# Users can manually place frida-gadget.so in jniLibs/ for device-specific builds
