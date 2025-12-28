cmake_minimum_required(VERSION 3.22.1)

project("hcefhook")

# Native hooking library using inline hooking
add_library(${PROJECT_NAME} SHARED
        native_hook.cpp)

target_link_libraries(${PROJECT_NAME}
        android
        log)

option(ENABLE_DOBBY "Enable Dobby inline hook engine" OFF)
if(ENABLE_DOBBY)
    find_library(DOBBY_LIB dobby)
    if(DOBBY_LIB)
        target_link_libraries(${PROJECT_NAME} ${DOBBY_LIB})
        target_compile_definitions(${PROJECT_NAME} PRIVATE USE_DOBBY)
    else()
        message(WARNING "Dobby library not found; set ENABLE_DOBBY=OFF or provide dobby.")
    endif()
endif()

# Download Frida Gadget at build time (optional - for full Frida support)
# Users can manually place frida-gadget.so in jniLibs/ for device-specific builds
