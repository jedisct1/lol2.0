#ifndef lol2_backend_neon_H
#define lol2_backend_neon_H

#include <arm_neon.h>
#include <stdint.h>

#include "backend_common.h"

typedef uint8x16_t aes_block_t;

#define AES_BLOCK_ZERO()      vmovq_n_u8(0)
#define AES_BLOCK_LOAD(P)     vld1q_u8(P)
#define AES_BLOCK_STORE(P, V) vst1q_u8((P), (V))
#define AES_BLOCK_XOR(A, B)   veorq_u8((A), (B))

#define AES_ENC(A, B) veorq_u8(vaesmcq_u8(vaeseq_u8(vmovq_n_u8(0), (A))), (B))

typedef struct {
    aes_block_t lo, hi;
} aes_block2_t;

static inline aes_block2_t
aes_block2_make(aes_block_t lo, aes_block_t hi)
{
    return (aes_block2_t) { lo, hi };
}

static inline aes_block2_t
aes_block2_zero(void)
{
    return aes_block2_make(AES_BLOCK_ZERO(), AES_BLOCK_ZERO());
}

static inline aes_block2_t
aes_block2_load(const uint8_t *p)
{
    return aes_block2_make(AES_BLOCK_LOAD(p), AES_BLOCK_LOAD(p + 16));
}

static inline void
aes_block2_store(uint8_t *p, aes_block2_t v)
{
    AES_BLOCK_STORE(p, v.lo);
    AES_BLOCK_STORE(p + 16, v.hi);
}

static inline aes_block2_t
aes_block2_xor(aes_block2_t a, aes_block2_t b)
{
    return aes_block2_make(AES_BLOCK_XOR(a.lo, b.lo), AES_BLOCK_XOR(a.hi, b.hi));
}

static inline aes_block2_t
aes_block2_sigma(aes_block2_t l)
{
    static const uint8_t idx_lo[16] = { 6, 7, 24, 25, 10, 11, 2, 3, 26, 27, 20, 21, 14, 15, 8, 9 };
    static const uint8_t idx_hi[16] = {
        18, 19, 0, 1, 16, 17, 4, 5, 28, 29, 30, 31, 12, 13, 22, 23
    };
    uint8x16x2_t t = { { l.lo, l.hi } };

    return aes_block2_make(vqtbl2q_u8(t, vld1q_u8(idx_lo)), vqtbl2q_u8(t, vld1q_u8(idx_hi)));
}

/* LFSR1 multiplies each 16-bit cell by y.
 * Its top bit selects the reduction constant.
 */
static inline aes_block_t
lambda1_half(aes_block_t h, uint16x8_t red)
{
    uint16x8_t h16 = vreinterpretq_u16_u8(h);
    uint16x8_t top = vreinterpretq_u16_s16(vshrq_n_s16(vreinterpretq_s16_u8(h), 15));

    return vreinterpretq_u8_u16(veorq_u16(vshlq_n_u16(h16, 1), vandq_u16(top, red)));
}

static inline aes_block2_t
aes_block2_lambda1(aes_block2_t h)
{
    return aes_block2_make(lambda1_half(h.lo, vld1q_u16(lol_lfsr1_red)),
                           lambda1_half(h.hi, vld1q_u16(lol_lfsr1_red + 8)));
}

static inline aes_block_t
lambda2_half(aes_block_t h, uint16x8_t sel)
{
    aes_block_t a = vreinterpretq_u8_u32(vshlq_n_u32(vreinterpretq_u32_u8(h), 5));
    aes_block_t b = vreinterpretq_u8_u16(vshrq_n_u16(vreinterpretq_u16_u8(h), 6));

    return vbslq_u8(vreinterpretq_u8_u16(sel), b, a);
}

static inline aes_block2_t
aes_block2_lambda2(aes_block2_t h)
{
    static const uint16_t sel_lo[8] = { 0xffff, 0, 0, 0xffff, 0xffff, 0, 0, 0 };
    static const uint16_t sel_hi[8] = { 0, 0xffff, 0xffff, 0, 0xffff, 0, 0xffff, 0 };

    return aes_block2_make(lambda2_half(h.lo, vld1q_u16(sel_lo)),
                           lambda2_half(h.hi, vld1q_u16(sel_hi)));
}

#endif
