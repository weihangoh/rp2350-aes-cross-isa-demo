#include <stdint.h>
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"
#include "aes_shared.h"
#include "aes_core.h"
#include "isa_switch.h"

#ifndef WORKER_ISA
#error WORKER_ISA must be ISA_ARM or ISA_RISCV
#endif

static void request_next_reboot(volatile aes_shared_t *ctx) {
    if (ctx->done || ctx->error) {
        /* final reset only returns control to core0 host for printing */
    } else if (ctx->next_isa == ISA_RISCV) {
        OTP_ARCHSEL |= CORE1_RISCV_BIT;
    } else {
        OTP_ARCHSEL &= ~CORE1_RISCV_BIT;
    }

    watchdog_hw->scratch[SCR_RUN_MAGIC_IDX] = SCR_RUN_MAGIC;
    watchdog_start_tick(12);
    watchdog_reboot(0, 0, 1);

    while (1) {
        __asm volatile ("" ::: "memory");
    }
}

#if WORKER_ISA == ISA_RISCV

static inline uint32_t read_mhartid(void) {
    uint32_t v;
    __asm volatile ("csrr %0, mhartid" : "=r"(v));
    return v;
}

static inline uint32_t read_marchid(void) {
    uint32_t v;
    __asm volatile ("csrr %0, marchid" : "=r"(v));
    return v;
}

static inline uint32_t read_misa(void) {
    uint32_t v;
    __asm volatile ("csrr %0, misa" : "=r"(v));
    return v;
}

#else

#define SCB_CPUID_ADDR 0xE000ED00u

static inline uint32_t read_arm_cpuid(void) {
    return *(volatile uint32_t *)SCB_CPUID_ADDR;
}

#endif

void worker_c_entry(void) {
    volatile aes_shared_t *ctx = aes_shared();

#if WORKER_ISA == ISA_ARM
    uint32_t worker_magic = WORKER_MAGIC_ARM;
    uint32_t arm_cpuid = read_arm_cpuid();
    uint32_t rv_mhartid = 0;
    uint32_t rv_marchid = 0;
    uint32_t rv_misa = 0;
#else
    uint32_t worker_magic = WORKER_MAGIC_RISCV;
    uint32_t arm_cpuid = 0;
    uint32_t rv_mhartid = read_mhartid();
    uint32_t rv_marchid = read_marchid();
    uint32_t rv_misa = read_misa();
#endif

    ctx->last_worker_magic = worker_magic;

    aes_worker_execute_one_state(ctx,
                                 WORKER_ISA,
                                 worker_magic,
                                 arm_cpuid,
                                 rv_mhartid,
                                 rv_marchid,
                                 rv_misa);

    request_next_reboot(ctx);
}
