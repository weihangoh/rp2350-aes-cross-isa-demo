#include "aes_core.h"

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

const aes_state_desc_t aes_states[41] = {
    { AES_FN_ADD_ROUND_KEY, 0 },

#define R(r) \
    { AES_FN_SUB_BYTES,     (r) }, \
    { AES_FN_SHIFT_ROWS,    (r) }, \
    { AES_FN_MIX_COLUMNS,   (r) }, \
    { AES_FN_ADD_ROUND_KEY, (r) }

    R(1), R(2), R(3), R(4), R(5), R(6), R(7), R(8), R(9),

#undef R

    { AES_FN_SUB_BYTES,     10 },
    { AES_FN_SHIFT_ROWS,    10 },
    { AES_FN_ADD_ROUND_KEY, 10 },

    { AES_FN_CTR_XOR,       0 }
};

const char *aes_fn_name(uint32_t fn) {
    switch (fn) {
    case AES_FN_ADD_ROUND_KEY: return "AddRoundKey";
    case AES_FN_SUB_BYTES:     return "SubBytes";
    case AES_FN_SHIFT_ROWS:    return "ShiftRows";
    case AES_FN_MIX_COLUMNS:   return "MixColumns";
    case AES_FN_CTR_XOR:       return "CTR_XOR";
    default:                   return "?";
    }
}

static void mem_copy_u8(uint8_t *dst, const uint8_t *src, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) dst[i] = src[i];
}

static void aes_add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    for (uint32_t i = 0; i < 16; ++i) state[i] ^= rk[i];
}

static void aes_sub_bytes(uint8_t state[16]) {
    for (uint32_t i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

static void aes_shift_rows(uint8_t s[16]) {
    uint8_t t;

    /* row 1: positions 1,5,9,13 rotate left 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;

    /* row 2: positions 2,6,10,14 rotate left 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;

    /* row 3: positions 3,7,11,15 rotate left 3 */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0x00u));
}

static void aes_mix_columns(uint8_t s[16]) {
    for (uint32_t c = 0; c < 4; ++c) {
        uint8_t *p = &s[4u * c];
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        uint8_t u = a0;

        p[0] ^= (uint8_t)(t ^ xtime((uint8_t)(a0 ^ a1)));
        p[1] ^= (uint8_t)(t ^ xtime((uint8_t)(a1 ^ a2)));
        p[2] ^= (uint8_t)(t ^ xtime((uint8_t)(a2 ^ a3)));
        p[3] ^= (uint8_t)(t ^ xtime((uint8_t)(a3 ^ u)));
    }
}

void aes128_key_expand(uint8_t rk[176], const uint8_t key[16]) {
    static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

    for (uint32_t i = 0; i < 16; ++i) rk[i] = key[i];

    uint32_t bytes = 16;
    uint32_t rci = 0;
    uint8_t temp[4];

    while (bytes < 176) {
        for (uint32_t i = 0; i < 4; ++i) temp[i] = rk[bytes - 4 + i];

        if ((bytes & 15u) == 0u) {
            uint8_t k = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rci++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];
        }

        for (uint32_t i = 0; i < 4; ++i) {
            rk[bytes] = rk[bytes - 16] ^ temp[i];
            bytes++;
        }
    }
}

uint32_t aes_hash16(const uint8_t s[16]) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < 16; ++i) {
        h ^= s[i];
        h *= 16777619u;
    }
    return h;
}

static uint64_t ctx_rng64(volatile aes_shared_t *ctx) {
    uint64_t x = ((uint64_t)ctx->rng_state_hi << 32) | ctx->rng_state_lo;
    x += 0x9E3779B97F4A7C15ull;

    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z = z ^ (z >> 31);

    ctx->rng_state_lo = (uint32_t)x;
    ctx->rng_state_hi = (uint32_t)(x >> 32);
    ctx->rng_draw_count++;

    return z;
}

static uint32_t choose_next_isa(volatile aes_shared_t *ctx, uint32_t this_isa) {
    switch (ctx->route_mode) {
    case AES_ROUTE_ALTERNATE:
        return this_isa == ISA_ARM ? ISA_RISCV : ISA_ARM;

    case AES_ROUTE_RANDOM_FREE:
        return (ctx_rng64(ctx) & 1u) ? ISA_RISCV : ISA_ARM;

    case AES_ROUTE_RANDOM_NO_REPEAT:
        return this_isa == ISA_ARM ? ISA_RISCV : ISA_ARM;

    default:
        ctx->error = 0xBAD00001u;
        return ISA_ARM;
    }
}

void aes_prepare_counter_block(volatile aes_shared_t *ctx) {
    for (uint32_t i = 0; i < 8; ++i) {
        ctx->state[i] = ctx->nonce[i];
    }

    uint8_t ctr[8];
    for (uint32_t i = 0; i < 8; ++i) ctr[i] = ctx->counter[i];

    uint32_t add = ctx->block_index;
    for (int i = 7; i >= 0 && add; --i) {
        uint32_t v = (uint32_t)ctr[i] + (add & 0xffu);
        ctr[i] = (uint8_t)v;
        add = (add >> 8) + (v >> 8);
    }

    for (uint32_t i = 0; i < 8; ++i) {
        ctx->state[8u + i] = ctr[i];
    }
}

static void aes_ctr_xor_write_output(volatile aes_shared_t *ctx) {
    uint32_t off = ctx->block_index * 16u;
    uint32_t remain = ctx->byte_len - off;
    if (remain > 16u) remain = 16u;

    for (uint32_t i = 0; i < remain; ++i) {
        ctx->ciphertext[off + i] = ctx->plaintext[off + i] ^ ctx->state[i];
    }
}

void aes128_encrypt_block_reference(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t s[16];
    mem_copy_u8(s, in, 16);

    aes_add_round_key(s, &rk[0]);

    for (uint32_t round = 1; round <= 9; ++round) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, &rk[16u * round]);
    }

    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, &rk[160]);

    mem_copy_u8(out, s, 16);
}

void aes_ctr_encrypt_reference(const uint8_t key[16], const uint8_t nonce[8], const uint8_t counter[8],
                               const uint8_t *plaintext, uint32_t len, uint8_t *ciphertext) {
    uint8_t rk[176];
    aes128_key_expand(rk, key);

    uint32_t blocks = (len + 15u) / 16u;
    for (uint32_t b = 0; b < blocks; ++b) {
        uint8_t ctrblk[16];
        uint8_t stream[16];

        for (uint32_t i = 0; i < 8; ++i) ctrblk[i] = nonce[i];

        uint8_t ctr[8];
        for (uint32_t i = 0; i < 8; ++i) ctr[i] = counter[i];

        uint32_t add = b;
        for (int i = 7; i >= 0 && add; --i) {
            uint32_t v = (uint32_t)ctr[i] + (add & 0xffu);
            ctr[i] = (uint8_t)v;
            add = (add >> 8) + (v >> 8);
        }

        for (uint32_t i = 0; i < 8; ++i) ctrblk[8u + i] = ctr[i];

        aes128_encrypt_block_reference(ctrblk, stream, rk);

        uint32_t off = b * 16u;
        uint32_t remain = len - off;
        if (remain > 16u) remain = 16u;

        for (uint32_t i = 0; i < remain; ++i) {
            ciphertext[off + i] = plaintext[off + i] ^ stream[i];
        }
    }
}

void aes_worker_execute_one_state(volatile aes_shared_t *ctx,
                                  uint32_t this_isa,
                                  uint32_t worker_magic,
                                  uint32_t arm_cpuid,
                                  uint32_t rv_mhartid,
                                  uint32_t rv_marchid,
                                  uint32_t rv_misa) {
    if (ctx->magic != AES_MAGIC) {
        ctx->error = AES_ERR_BAD_MAGIC;
        ctx->done = 1;
        return;
    }

    if (ctx->current_isa != this_isa) {
        ctx->error = AES_ERR_BAD_ISA;
        ctx->done = 1;
        return;
    }

    ctx->last_worker_magic = worker_magic;
    ctx->last_worker_reported_isa = this_isa;
    ctx->last_arm_cpuid = arm_cpuid;
    ctx->last_rv_mhartid = rv_mhartid;
    ctx->last_rv_marchid = rv_marchid;
    ctx->last_rv_misa = rv_misa;

    uint32_t sid = ctx->state_id;
    uint32_t block_for_event = ctx->block_index;
    uint32_t generation_for_event = ctx->generation;

    if (sid >= 41u) {
        ctx->error = AES_ERR_BAD_STATE;
        ctx->done = 1;
        return;
    }

    aes_state_desc_t d = aes_states[sid];

    uint32_t before = aes_hash16((const uint8_t *)ctx->state);

    switch (d.fn) {
    case AES_FN_ADD_ROUND_KEY:
        aes_add_round_key((uint8_t *)ctx->state, (const uint8_t *)&ctx->round_keys[16u * d.round]);
        break;
    case AES_FN_SUB_BYTES:
        aes_sub_bytes((uint8_t *)ctx->state);
        break;
    case AES_FN_SHIFT_ROWS:
        aes_shift_rows((uint8_t *)ctx->state);
        break;
    case AES_FN_MIX_COLUMNS:
        aes_mix_columns((uint8_t *)ctx->state);
        break;
    case AES_FN_CTR_XOR:
        aes_ctr_xor_write_output(ctx);
        break;
    default:
        ctx->error = AES_ERR_BAD_FUNCTION;
        ctx->done = 1;
        return;
    }

    uint32_t after = aes_hash16((const uint8_t *)ctx->state);

    uint32_t next_isa = this_isa;
    uint32_t next_state = sid;
    uint32_t has_next = 1u;

    if (sid < 40u) {
        next_state = sid + 1u;
        next_isa = choose_next_isa(ctx, this_isa);
    } else {
        if ((ctx->block_index + 1u) < ctx->block_count) {
            ctx->block_index++;
            aes_prepare_counter_block(ctx);
            next_state = 0u;
            next_isa = choose_next_isa(ctx, this_isa);
        } else {
            has_next = 0u;
            ctx->done = 1u;
            ctx->launch_request = LAUNCH_NONE;
        }
    }

    uint32_t ev = ctx->event_count;
    if (ev < AES_EVENT_LOG_N) {
        ctx->events[ev].generation = generation_for_event;
        ctx->events[ev].block = block_for_event;
        ctx->events[ev].state = sid;
        ctx->events[ev].this_isa = this_isa;
        ctx->events[ev].fn = d.fn;
        ctx->events[ev].round = d.round;
        ctx->events[ev].rng_draw_count = ctx->rng_draw_count;
        ctx->events[ev].next_state = has_next ? next_state : 0xffffffffu;
        ctx->events[ev].next_isa = has_next ? next_isa : 0xffffffffu;
        ctx->events[ev].did_change_isa = has_next && (next_isa != this_isa);
        ctx->events[ev].state_hash_before = before;
        ctx->events[ev].state_hash_after = after;

        ctx->events[ev].launch_archsel_status = ctx->pending_archsel_status;
        ctx->events[ev].launch_requested_isa = ctx->pending_launch_isa;
        ctx->events[ev].worker_magic = worker_magic;
        ctx->events[ev].worker_reported_isa = this_isa;

        ctx->events[ev].arm_cpuid = arm_cpuid;

        ctx->events[ev].rv_mhartid = rv_mhartid;
        ctx->events[ev].rv_marchid = rv_marchid;
        ctx->events[ev].rv_misa = rv_misa;

        ctx->event_count = ev + 1u;
    } else {
        ctx->error = AES_ERR_LOG_FULL;
        ctx->done = 1u;
        ctx->launch_request = LAUNCH_NONE;
        has_next = 0u;
    }

    ctx->last_stage = sid;
    ctx->last_round = d.round;
    ctx->last_function = d.fn;

    if (this_isa == ISA_ARM) ctx->arm_stage_count++;
    else ctx->riscv_stage_count++;

    if (has_next) {
        if (next_isa != this_isa) ctx->isa_change_count++;
        else ctx->same_isa_relaunch_count++;

        ctx->next_state_id = next_state;
        ctx->next_isa = next_isa;

        ctx->state_id = next_state;
        ctx->current_isa = next_isa;
        ctx->launch_request = LAUNCH_CORE1;
    }

    ctx->reset_continuation_count++;
    ctx->generation++;
}
