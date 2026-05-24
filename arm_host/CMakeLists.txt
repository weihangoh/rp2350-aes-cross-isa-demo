cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Pico platform")
set(PICO_BOARD pico2_w CACHE STRING "Pico board")

if(NOT DEFINED ENV{PICO_SDK_PATH})
    message(FATAL_ERROR "PICO_SDK_PATH is not set")
endif()

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(arm_host C CXX ASM)
pico_sdk_init()

add_executable(arm_host
    main.c
    ../common/aes_core.c
)

target_include_directories(arm_host PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../common
)

target_link_libraries(arm_host
    pico_stdlib
    pico_multicore
    hardware_watchdog
)

pico_enable_stdio_usb(arm_host 1)
pico_enable_stdio_uart(arm_host 0)

pico_add_extra_outputs(arm_host)
