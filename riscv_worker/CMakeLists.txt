cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350-riscv CACHE STRING "Pico platform")
set(PICO_BOARD pico2_w CACHE STRING "Pico board")

if(NOT DEFINED ENV{PICO_SDK_PATH})
    message(FATAL_ERROR "PICO_SDK_PATH is not set")
endif()

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(riscv_worker C ASM)
pico_sdk_init()

add_executable(riscv_worker
    worker_stub.S
    worker.c
    ../common/aes_core.c
)

target_include_directories(riscv_worker PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../common
)

target_compile_definitions(riscv_worker PRIVATE
    WORKER_ISA=ISA_RISCV
)

target_compile_options(riscv_worker PRIVATE
    -ffreestanding
    -fno-builtin
    -fdata-sections
    -ffunction-sections
)

target_link_options(riscv_worker PRIVATE
    -nostdlib
    -Wl,-T,${CMAKE_CURRENT_LIST_DIR}/worker.ld
    -Wl,--gc-sections
    -Wl,-e,riscv_worker_entry
)

target_link_libraries(riscv_worker
    hardware_watchdog
)

set(WORKER_BIN ${CMAKE_CURRENT_BINARY_DIR}/riscv_worker.bin)
set(WORKER_HEADER ${CMAKE_CURRENT_LIST_DIR}/../arm_host/worker_riscv_blob.h)

add_custom_command(
    OUTPUT ${WORKER_BIN}
    COMMAND ${CMAKE_OBJCOPY} -O binary
            ${CMAKE_CURRENT_BINARY_DIR}/riscv_worker.elf
            ${WORKER_BIN}
    DEPENDS riscv_worker
    VERBATIM
)

add_custom_command(
    OUTPUT ${WORKER_HEADER}
    COMMAND ${CMAKE_COMMAND}
            -DINPUT=${WORKER_BIN}
            -DOUTPUT=${WORKER_HEADER}
            -DSYMBOL=worker_riscv_blob
            -P ${CMAKE_CURRENT_LIST_DIR}/../common/bin2h.cmake
    DEPENDS ${WORKER_BIN} ${CMAKE_CURRENT_LIST_DIR}/../common/bin2h.cmake
    VERBATIM
)

add_custom_target(worker_riscv_blob ALL
    DEPENDS ${WORKER_HEADER}
)
