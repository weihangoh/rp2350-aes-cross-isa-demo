#pragma once
#include <stdint.h>
#include "aes_shared.h"

typedef struct {
    uint8_t fn;
    uint8_t round;
} aes_state_desc_t;

extern const aes_state_desc_t aes_states[41];

void aes128_key_expand(uint8_t round_keys[176], const uint8_t key[16]);
void aes_prepare_counter_block(volatile aes_shared_t *ctx);
void aes_worker_execute_one_state(volatile aes_shared_t *ctx,
                                  uint32_t this_isa,
                                  uint32_t worker_magic,
                                  uint32_t arm_cpuid,
                                  uint32_t rv_mhartid,
                                  uint32_t rv_marchid,
                                  uint32_t rv_misa);
void aes128_encrypt_block_reference(const uint8_t in[16], uint8_t out[16], const uint8_t round_keys[176]);
void aes_ctr_encrypt_reference(const uint8_t key[16], const uint8_t nonce[8], const uint8_t counter[8],
                               const uint8_t *plaintext, uint32_t len, uint8_t *ciphertext);
uint32_t aes_hash16(const uint8_t s[16]);
const char *aes_fn_name(uint32_t fn);
