#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/multicore.h"
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"

#include "isa_switch.h"
#include "aes_shared.h"
#include "aes_core.h"

#include "worker_arm_blob.h"
#include "worker_riscv_blob.h"

#define AES_DEBUG_PRINT_EACH_STAGE 0
#define AES_USB_WAIT_FINAL_MS      10000
#define AES_USB_WAIT_DEBUG_MS      8000

static bool g_console_enabled = false;

#define LOGF(...) do {                         \
    if (g_console_enabled) {                   \
        printf(__VA_ARGS__);                   \
    }                                          \
} while (0)

static void enable_console_and_wait(uint32_t timeout_ms) {
    stdio_init_all();

    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    while (!stdio_usb_connected() && !time_reached(deadline)) {
        sleep_ms(10);
    }

    /* Give terminal tools a little time after CDC reports connected. */
    sleep_ms(250);
    g_console_enabled = true;
}

static uint32_t g_core1_stack[1024];

static void print_hex(const char *label, const uint8_t *p, uint32_t n) {
    printf("%s", label);
    for (uint32_t i = 0; i < n; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static void clear_ctx(volatile aes_shared_t *ctx) {
    uint8_t *p = (uint8_t *)ctx;
    for (uint32_t i = 0; i < sizeof(*ctx); ++i) p[i] = 0;
}

static void init_experiment(volatile aes_shared_t *ctx) {
    clear_ctx(ctx);

    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    static const uint8_t nonce[8] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7
    };

    static const uint8_t counter[8] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    const char *msg =
        "Cross-ISA AES CTR: each primitive chooses the next state and next ISA.";

    uint32_t len = (uint32_t)strlen(msg);
    if (len > AES_MAX_TEXT) len = AES_MAX_TEXT;

    ctx->magic = AES_MAGIC;
    ctx->byte_len = len;
    ctx->block_count = (len + 15u) / 16u;
    ctx->block_index = 0;
    ctx->state_id = 0;
    ctx->next_state_id = 0;
    ctx->generation = 0;

    ctx->route_mode = AES_ROUTE_RANDOM_FREE;

    ctx->rng_seed_lo = 0x12345678u;
    ctx->rng_seed_hi = 0xa5e5c0deu;
    ctx->rng_state_lo = ctx->rng_seed_lo;
    ctx->rng_state_hi = ctx->rng_seed_hi;

    ctx->current_isa = ISA_RISCV;
    ctx->next_isa = ISA_RISCV;
    ctx->launch_request = LAUNCH_CORE1;

    for (uint32_t i = 0; i < 16; ++i) ctx->key[i] = key[i];
    for (uint32_t i = 0; i < 8; ++i) {
        ctx->nonce[i] = nonce[i];
        ctx->counter[i] = counter[i];
    }
    for (uint32_t i = 0; i < len; ++i) {
        ctx->plaintext[i] = (uint8_t)msg[i];
    }

    aes128_key_expand((uint8_t *)ctx->round_keys, (const uint8_t *)ctx->key);
    aes_prepare_counter_block(ctx);

    watchdog_hw->scratch[SCR_RUN_MAGIC_IDX] = SCR_RUN_MAGIC;
}

static void stage_worker_blob(uint32_t isa) {
    if (isa == ISA_RISCV) {
        memcpy((void *)WORKER_LOAD_ADDR, worker_riscv_blob, worker_riscv_blob_LEN);
    } else {
        memcpy((void *)WORKER_LOAD_ADDR, worker_arm_blob, worker_arm_blob_LEN);
    }
}

static void set_core1_isa(uint32_t isa) {
    if (isa == ISA_RISCV) {
        OTP_ARCHSEL |= CORE1_RISCV_BIT;
    } else {
        OTP_ARCHSEL &= ~CORE1_RISCV_BIT;
    }
}

static void launch_requested_worker(volatile aes_shared_t *ctx) {
    uint32_t isa = ctx->next_isa;

    LOGF("Launching core1: block=%lu state=%lu expected_isa=%s gen=%lu\n",
           (unsigned long)ctx->block_index,
           (unsigned long)ctx->state_id,
           isa_name(isa),
           (unsigned long)ctx->generation);

    set_core1_isa(isa);
    multicore_reset_core1();
    sleep_ms(10);

    stage_worker_blob(isa);

    uint32_t status = OTP_ARCHSEL_STATUS;

    ctx->pending_archsel_status = status;
    ctx->pending_launch_isa = isa;

    printf("ARCHSEL_STATUS before launch: core0=%s core1=%s\n",
           arch_name_from_bit(status, CORE0_RISCV_BIT),
           arch_name_from_bit(status, CORE1_RISCV_BIT));

    gpio_put(12, (ctx->generation & 1u) ? 1 : 0);
    if (isa == ISA_RISCV) {
        multicore_launch_core1_raw(
            (void (*)(void))(uintptr_t)(WORKER_LOAD_ADDR + 4u),
            g_core1_stack + (sizeof(g_core1_stack) / sizeof(g_core1_stack[0])),
            WORKER_LOAD_ADDR
        );
    } else {
        uint32_t reset_vector = *(volatile uint32_t *)(WORKER_LOAD_ADDR + 4u);
        multicore_launch_core1_raw(
            (void (*)(void))(uintptr_t)reset_vector,
            g_core1_stack + (sizeof(g_core1_stack) / sizeof(g_core1_stack[0])),
            WORKER_LOAD_ADDR
        );
    }

    while (1) {
        sleep_ms(1000);
    }
}

static bool verify_ciphertext(volatile aes_shared_t *ctx) {
    uint8_t ref[AES_MAX_TEXT];
    for (uint32_t i = 0; i < AES_MAX_TEXT; ++i) ref[i] = 0;

    aes_ctr_encrypt_reference((const uint8_t *)ctx->key,
                              (const uint8_t *)ctx->nonce,
                              (const uint8_t *)ctx->counter,
                              (const uint8_t *)ctx->plaintext,
                              ctx->byte_len,
                              ref);

    for (uint32_t i = 0; i < ctx->byte_len; ++i) {
        if (ref[i] != ctx->ciphertext[i]) return false;
    }
    return true;
}

static const char *route_mode_name(uint32_t mode) {
    switch (mode) {
    case AES_ROUTE_ALTERNATE:
        return "ALTERNATE";
    case AES_ROUTE_RANDOM_FREE:
        return "RANDOM_FREE";
    case AES_ROUTE_RANDOM_NO_REPEAT:
        return "RANDOM_NO_REPEAT";
    default:
        return "UNKNOWN";
    }
}

static void print_events(volatile aes_shared_t *ctx) {
    printf("\nEvent log:\n");
    printf("gen block stg launch  worker  function      rnd next_stg next_isa change before    after     proof\n");

    uint32_t n = ctx->event_count;
    if (n > AES_EVENT_LOG_N) n = AES_EVENT_LOG_N;

    for (uint32_t i = 0; i < n; ++i) {
        const aes_event_t *e = (const aes_event_t *)&ctx->events[i];
        const char *launch_core1 =
            arch_name_from_bit(e->launch_archsel_status, CORE1_RISCV_BIT);

        printf("%03lu %5lu %3lu %-7s %-7s %-13s %3lu ",
               (unsigned long)e->generation,
               (unsigned long)e->block,
               (unsigned long)e->state,
               launch_core1,
               isa_name(e->worker_reported_isa),
               aes_fn_name(e->fn),
               (unsigned long)e->round);

        if (e->next_state == 0xffffffffu) {
            printf("DONE     DONE     ");
        } else {
            printf("%8lu %-8s ",
                   (unsigned long)e->next_state,
                   isa_name(e->next_isa));
        }

        printf("%6lu %08lx %08lx ",
               (unsigned long)e->did_change_isa,
               (unsigned long)e->state_hash_before,
               (unsigned long)e->state_hash_after);

        if (e->worker_reported_isa == ISA_RISCV) {
            printf("RVI1 mhartid=%08lx marchid=%08lx misa=%08lx\n",
                   (unsigned long)e->rv_mhartid,
                   (unsigned long)e->rv_marchid,
                   (unsigned long)e->rv_misa);
        } else {
            printf("ARM1 cpuid=%08lx\n",
                   (unsigned long)e->arm_cpuid);
        }
    }
}

static void print_summary(volatile aes_shared_t *ctx) {
    printf("\n=== randomized self-directed cross-ISA AES complete ===\n");
    printf("error                     = 0x%08lx\n", (unsigned long)ctx->error);
    printf("route_mode                = %s\n", route_mode_name(ctx->route_mode));
    printf("seed                      = 0x%08lx%08lx\n",
           (unsigned long)ctx->rng_seed_hi,
           (unsigned long)ctx->rng_seed_lo);
    printf("byte_len                  = %lu\n", (unsigned long)ctx->byte_len);
    printf("blocks                    = %lu\n", (unsigned long)ctx->block_count);
    printf("states executed           = %lu\n", (unsigned long)ctx->generation);
    printf("reset continuations       = %lu\n", (unsigned long)ctx->reset_continuation_count);
    printf("observed ISA changes      = %lu\n", (unsigned long)ctx->isa_change_count);
    printf("same-ISA relaunches       = %lu\n", (unsigned long)ctx->same_isa_relaunch_count);
    printf("ARM stages                = %lu\n", (unsigned long)ctx->arm_stage_count);
    printf("RISC-V stages             = %lu\n", (unsigned long)ctx->riscv_stage_count);
    printf("rng draws                 = %lu\n", (unsigned long)ctx->rng_draw_count);
    printf("last worker ISA           = %s\n", isa_name(ctx->last_worker_reported_isa));
    printf("last ARM CPUID            = 0x%08lx\n", (unsigned long)ctx->last_arm_cpuid);
    printf("last RV mhartid           = 0x%08lx\n", (unsigned long)ctx->last_rv_mhartid);
    printf("last RV marchid           = 0x%08lx\n", (unsigned long)ctx->last_rv_marchid);
    printf("last RV misa              = 0x%08lx\n", (unsigned long)ctx->last_rv_misa);

    print_hex("plaintext  = ", (const uint8_t *)ctx->plaintext, ctx->byte_len);
    print_hex("ciphertext = ", (const uint8_t *)ctx->ciphertext, ctx->byte_len);

    print_hex("key        = ", (const uint8_t *)ctx->key, 16);
    print_hex("nonce      = ", (const uint8_t *)ctx->nonce, 8);
    print_hex("counter    = ", (const uint8_t *)ctx->counter, 8);

    bool ok = verify_ciphertext(ctx);
    printf("AES-CTR verification      = %s\n", ok ? "PASS" : "FAIL");

    print_events(ctx);
}

int main(void) {
    volatile aes_shared_t *ctx = aes_shared();
    bool was_wdog = watchdog_caused_reboot();

    bool fresh_start = (!was_wdog || ctx->magic != AES_MAGIC);
    bool final_state = (!fresh_start && (ctx->done || ctx->error));

    gpio_init(12);
    gpio_set_dir(12, GPIO_OUT);

#if AES_DEBUG_PRINT_EACH_STAGE
    enable_console_and_wait(AES_USB_WAIT_DEBUG_MS);
#else
    if (fresh_start || final_state) {
        enable_console_and_wait(AES_USB_WAIT_FINAL_MS);
    }
#endif

    LOGF("\n=== randomized self-directed cross-ISA AES-CTR ===\n");
    LOGF("was_wdog                  = %s\n", was_wdog ? "true" : "false");
    LOGF("ctx magic                 = 0x%08lx\n", (unsigned long)ctx->magic);
    LOGF("watchdog scratch0         = 0x%08lx\n",
         (unsigned long)watchdog_hw->scratch[SCR_RUN_MAGIC_IDX]);

    if (fresh_start) {
        LOGF("Initializing new AES experiment.\n");
        init_experiment(ctx);
    }

    if (ctx->done || ctx->error) {
        print_summary(ctx);
        printf("\nPower-cycle or press reset to start a fresh run.\n");
        watchdog_hw->scratch[SCR_RUN_MAGIC_IDX] = 0;

        while (1) {
            sleep_ms(1000);
        }
    }

    if (ctx->launch_request == LAUNCH_CORE1) {
        launch_requested_worker(ctx);
    }

    if (!g_console_enabled) {
        enable_console_and_wait(AES_USB_WAIT_FINAL_MS);
    }

    printf("No launch request and not done; stopping. error=0x%08lx\n",
           (unsigned long)ctx->error);

    while (1) {
        sleep_ms(1000);
    }
}
