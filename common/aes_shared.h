#pragma once
#include <stdint.h>
#include "isa_switch.h"

#define AES_MAGIC             0x41455358u   /* "AESX" */
#define AES_MAX_TEXT          256u
#define AES_EVENT_LOG_N       256u

#define AES_ROUTE_ALTERNATE        0u
#define AES_ROUTE_RANDOM_FREE      1u
#define AES_ROUTE_RANDOM_NO_REPEAT 2u

#define LAUNCH_NONE           0u
#define LAUNCH_CORE1          1u

#define AES_FN_ADD_ROUND_KEY  1u
#define AES_FN_SUB_BYTES      2u
#define AES_FN_SHIFT_ROWS     3u
#define AES_FN_MIX_COLUMNS    4u
#define AES_FN_CTR_XOR        5u

#define AES_ERR_NONE          0u
#define AES_ERR_BAD_MAGIC     1u
#define AES_ERR_BAD_STATE     2u
#define AES_ERR_BAD_FUNCTION  3u
#define AES_ERR_BAD_ISA       4u
#define AES_ERR_LOG_FULL      5u

#define SCR_RUN_MAGIC_IDX     0
#define SCR_RUN_MAGIC         0x41455350u   /* "AESP" */

typedef struct {
    uint32_t generation;
    uint32_t block;
    uint32_t state;
    uint32_t this_isa;
    uint32_t fn;
    uint32_t round;
    uint32_t rng_draw_count;
    uint32_t next_state;
    uint32_t next_isa;
    uint32_t did_change_isa;
    uint32_t state_hash_before;
    uint32_t state_hash_after;

    /* ISA proof fields */
    uint32_t launch_archsel_status;
    uint32_t launch_requested_isa;
    uint32_t worker_magic;
    uint32_t worker_reported_isa;

    uint32_t arm_cpuid;

    uint32_t rv_mhartid;
    uint32_t rv_marchid;
    uint32_t rv_misa;
} aes_event_t;

typedef struct {
    volatile uint32_t magic;

    volatile uint32_t launch_request;
    volatile uint32_t current_isa;
    volatile uint32_t next_isa;

    volatile uint32_t block_index;
    volatile uint32_t block_count;
    volatile uint32_t byte_len;

    volatile uint32_t state_id;        /* current AES primitive state, 0..40 */
    volatile uint32_t next_state_id;   /* chosen by current worker */
    volatile uint32_t generation;      /* total AES primitive states executed */

    volatile uint32_t route_mode;

    volatile uint32_t rng_seed_lo;
    volatile uint32_t rng_seed_hi;
    volatile uint32_t rng_state_lo;
    volatile uint32_t rng_state_hi;
    volatile uint32_t rng_draw_count;

    volatile uint32_t reset_continuation_count;
    volatile uint32_t isa_change_count;
    volatile uint32_t same_isa_relaunch_count;
    volatile uint32_t arm_stage_count;
    volatile uint32_t riscv_stage_count;

    volatile uint32_t done;
    volatile uint32_t error;

    uint8_t key[16];
    uint8_t round_keys[176];

    uint8_t nonce[8];
    uint8_t counter[8];

    uint8_t state[16];
    uint8_t plaintext[AES_MAX_TEXT];
    uint8_t ciphertext[AES_MAX_TEXT];

    volatile uint32_t last_stage;
    volatile uint32_t last_round;
    volatile uint32_t last_function;
    volatile uint32_t last_worker_magic;

    volatile uint32_t pending_archsel_status;
    volatile uint32_t pending_launch_isa;

    volatile uint32_t last_worker_reported_isa;
    volatile uint32_t last_arm_cpuid;

    volatile uint32_t last_rv_mhartid;
    volatile uint32_t last_rv_marchid;
    volatile uint32_t last_rv_misa;

    volatile uint32_t event_count;
    aes_event_t events[AES_EVENT_LOG_N];
} aes_shared_t;

static inline volatile aes_shared_t *aes_shared(void) {
    return (volatile aes_shared_t *)AES_SHARED_ADDR;
}
