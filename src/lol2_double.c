#include <string.h>

#include "../include/lol2.h"
#include "backend.h"

typedef struct {
    aes_block2_t l, h;
    aes_block_t  n0, n1;
    aes_block_t  s0, s1, s2, s3;
} core_t;

static inline aes_block2_t
scout(core_t *c, lol2d_lfsr variant)
{
    aes_block_t  g0, g1, z0, z1, t1, t3;
    aes_block2_t f;

    g0 = AES_ENC(c->s1, c->n0);
    g1 = AES_ENC(c->s3, c->n1);
    z0 = AES_ENC(g0, c->n0);
    z1 = AES_ENC(g1, c->n1);

    c->n0 = AES_ENC(c->n0, c->l.lo);
    c->n1 = AES_ENC(c->n1, c->l.hi);

    if (variant == LOL2D_LFSR1) {
        f = aes_block2_lambda1(c->h);
    } else {
        f = aes_block2_lambda2(c->h);
    }
    f    = aes_block2_xor(f, aes_block2_sigma(c->l));
    c->l = c->h;
    c->h = f;

    t1    = AES_ENC(c->s0, c->s1);
    t3    = AES_ENC(c->s2, c->s3);
    c->s0 = AES_BLOCK_XOR(c->s0, AES_BLOCK_XOR(g1, f.lo));
    c->s2 = AES_BLOCK_XOR(c->s2, AES_BLOCK_XOR(g0, f.hi));
    c->s1 = t1;
    c->s3 = t3;

    return aes_block2_make(z1, z0);
}

static inline void
scinit_round(core_t *c, lol2d_lfsr variant)
{
    aes_block2_t z = scout(c, variant);

    c->n0 = AES_BLOCK_XOR(c->n0, z.lo);
    c->n1 = AES_BLOCK_XOR(c->n1, z.hi);
    c->h  = aes_block2_xor(c->h, z);
}

static inline void
scinit(core_t *c, aes_block2_t key, lol2d_lfsr variant)
{
    int i;

    for (i = 0; i < 12; i++) {
        scinit_round(c, variant);
    }
    c->h = aes_block2_xor(c->h, key);
}

static inline void
load_core(core_t *c, const uint8_t *key, const uint8_t *iv)
{
    c->l  = aes_block2_zero();
    c->h  = aes_block2_zero();
    c->n0 = AES_BLOCK_ZERO();
    c->n1 = AES_BLOCK_ZERO();
    c->s0 = AES_BLOCK_LOAD(key);
    c->s2 = AES_BLOCK_LOAD(key + 16);
    c->s1 = AES_BLOCK_LOAD(iv);
    c->s3 = AES_BLOCK_LOAD(iv + 16);
}

static void
core_from_state(core_t *c, const lol2d_state *st)
{
    const uint8_t *b = st->blocks;

    c->l  = aes_block2_load(b);
    c->h  = aes_block2_load(b + 32);
    c->n0 = AES_BLOCK_LOAD(b + 64);
    c->n1 = AES_BLOCK_LOAD(b + 80);
    c->s0 = AES_BLOCK_LOAD(b + 96);
    c->s1 = AES_BLOCK_LOAD(b + 112);
    c->s2 = AES_BLOCK_LOAD(b + 128);
    c->s3 = AES_BLOCK_LOAD(b + 144);
}

static void
core_to_state(lol2d_state *st, const core_t *c)
{
    uint8_t *b = st->blocks;

    aes_block2_store(b, c->l);
    aes_block2_store(b + 32, c->h);
    AES_BLOCK_STORE(b + 64, c->n0);
    AES_BLOCK_STORE(b + 80, c->n1);
    AES_BLOCK_STORE(b + 96, c->s0);
    AES_BLOCK_STORE(b + 112, c->s1);
    AES_BLOCK_STORE(b + 128, c->s2);
    AES_BLOCK_STORE(b + 144, c->s3);
}

/* Do not unroll this loop.
 * On Apple Silicon, unrolling spills NEON registers and halves throughput.
 */
static inline void
run_blocks(core_t *c, uint8_t *dst, const uint8_t *src, size_t nblocks, lol2d_lfsr variant)
{
    size_t i;

    for (i = 0; i < nblocks; i++) {
        aes_block2_t z = scout(c, variant);

        if (src != NULL) {
            z = aes_block2_xor(z, aes_block2_load(src));
            src += 32;
        }
        aes_block2_store(dst, z);
        dst += 32;
    }
}

static void
run_ks_lfsr1(core_t *c, uint8_t *dst, size_t n)
{
    run_blocks(c, dst, NULL, n, LOL2D_LFSR1);
}

static void
run_ks_lfsr2(core_t *c, uint8_t *dst, size_t n)
{
    run_blocks(c, dst, NULL, n, LOL2D_LFSR2);
}

static void
run_xor_lfsr1(core_t *c, uint8_t *dst, const uint8_t *src, size_t n)
{
    run_blocks(c, dst, src, n, LOL2D_LFSR1);
}

static void
run_xor_lfsr2(core_t *c, uint8_t *dst, const uint8_t *src, size_t n)
{
    run_blocks(c, dst, src, n, LOL2D_LFSR2);
}

static void
run_blocks_dispatch(core_t *c, uint8_t *dst, const uint8_t *src, size_t nblocks, lol2d_lfsr variant)
{
    if (src == NULL) {
        if (variant == LOL2D_LFSR1) {
            run_ks_lfsr1(c, dst, nblocks);
        } else {
            run_ks_lfsr2(c, dst, nblocks);
        }
    } else {
        if (variant == LOL2D_LFSR1) {
            run_xor_lfsr1(c, dst, src, nblocks);
        } else {
            run_xor_lfsr2(c, dst, src, nblocks);
        }
    }
}

void
lol2d_init(lol2d_state *st, const uint8_t *key, const uint8_t *iv, lol2d_lfsr variant)
{
    core_t c;

    load_core(&c, key, iv);
    scinit(&c, aes_block2_load(key), variant);
    core_to_state(st, &c);
    st->ks_used = 32;
    st->variant = (uint8_t) variant;
}

static void
stream(lol2d_state *st, uint8_t *dst, const uint8_t *src, size_t n)
{
    lol2d_lfsr variant = (lol2d_lfsr) st->variant;
    core_t     c;
    size_t     nblocks;

    if (st->ks_used < 32) {
        size_t         take = 32 - st->ks_used;
        const uint8_t *ks   = st->ks + st->ks_used;
        size_t         i;

        if (take > n) {
            take = n;
        }
        if (src != NULL) {
            for (i = 0; i < take; i++) {
                dst[i] = (uint8_t) (src[i] ^ ks[i]);
            }
            src += take;
        } else {
            memcpy(dst, ks, take);
        }
        st->ks_used += (uint8_t) take;
        dst += take;
        n -= take;
    }
    if (n == 0) {
        return;
    }

    core_from_state(&c, st);

    nblocks = n / 32;
    if (nblocks > 0) {
        run_blocks_dispatch(&c, dst, src, nblocks, variant);
        dst += nblocks * 32;
        if (src != NULL) {
            src += nblocks * 32;
        }
        n -= nblocks * 32;
    }

    if (n > 0) {
        size_t i;

        aes_block2_store(st->ks, scout(&c, variant));
        st->ks_used = (uint8_t) n;
        if (src != NULL) {
            for (i = 0; i < n; i++) {
                dst[i] = (uint8_t) (src[i] ^ st->ks[i]);
            }
        } else {
            memcpy(dst, st->ks, n);
        }
    } else {
        st->ks_used = 32;
    }

    core_to_state(st, &c);
}

void
lol2d_keystream(lol2d_state *st, uint8_t *out, size_t n)
{
    stream(st, out, NULL, n);
}

void
lol2d_xor(lol2d_state *st, uint8_t *dst, const uint8_t *src, size_t n)
{
    stream(st, dst, src, n);
}

typedef struct {
    aes_block_t e0, e1, e2, e3, e4, e5;
} mac_t;

static inline void
upd_e(mac_t *m, aes_block_t d0, aes_block_t d1)
{
    aes_block_t u = AES_ENC(m->e5, m->e0);

    m->e5 = AES_ENC(m->e4, d1);
    m->e4 = AES_ENC(m->e3, d1);
    m->e3 = AES_ENC(m->e2, m->e3);
    m->e2 = AES_ENC(m->e1, d0);
    m->e1 = AES_ENC(m->e0, d0);
    m->e0 = u;
}

static inline void
upd_e_bytes(mac_t *m, const uint8_t d[32])
{
    upd_e(m, AES_BLOCK_LOAD(d), AES_BLOCK_LOAD(d + 16));
}

static void
upd_e_partial(mac_t *m, const uint8_t *d, size_t n)
{
    uint8_t buf[32] = { 0 };

    memcpy(buf, d, n);
    upd_e_bytes(m, buf);
}

static inline void
put_bitlen128(uint8_t p[16], size_t len)
{
    uint64_t lo = (uint64_t) len << 3;
    uint64_t hi = (uint64_t) len >> 61;
    int      i;

    for (i = 0; i < 8; i++) {
        p[i]     = (uint8_t) (lo >> (8 * i));
        p[8 + i] = (uint8_t) (hi >> (8 * i));
    }
}

static inline void
encode_lengths(uint8_t theta[32], size_t ad_len, size_t msg_len)
{
    put_bitlen128(theta, ad_len);
    put_bitlen128(theta + 16, msg_len);
}

/* Keep this inlined so dispatch arguments remain constants.
 * Otherwise, clang adds branches and spills in the block loop.
 */
__attribute__((always_inline)) static inline void
aead(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *ad, size_t ad_len,
     const uint8_t *key, const uint8_t *iv, uint8_t tag[LOL2D_TAG_BYTES], int decrypting,
     lol2d_lfsr variant)
{
    size_t       total_msg = len;
    size_t       total_ad  = ad_len;
    aes_block2_t k         = aes_block2_load(key);
    core_t       c;
    mac_t        m;
    uint8_t      theta[32];

    load_core(&c, key, iv);
    scinit(&c, k, variant);

    m.e0 = c.n0;
    m.e1 = c.n1;
    m.e2 = c.s0;
    m.e3 = c.s1;
    m.e4 = c.s2;
    m.e5 = c.s3;

    while (ad_len >= 32) {
        upd_e_bytes(&m, ad);
        ad += 32;
        ad_len -= 32;
    }
    if (ad_len > 0) {
        upd_e_partial(&m, ad, ad_len);
    }

    while (len >= 32) {
        aes_block2_t z    = scout(&c, variant);
        aes_block2_t data = aes_block2_load(in);

        if (decrypting) {
            aes_block2_t msg = aes_block2_xor(data, z);

            aes_block2_store(out, msg);
            upd_e(&m, msg.lo, msg.hi);
        } else {
            upd_e(&m, data.lo, data.hi);
            aes_block2_store(out, aes_block2_xor(data, z));
        }
        in += 32;
        out += 32;
        len -= 32;
    }
    if (len > 0) {
        uint8_t zb[32];
        uint8_t block[32] = { 0 };
        size_t  i;

        aes_block2_store(zb, scout(&c, variant));
        memcpy(block, in, len);
        for (i = 0; i < len; i++) {
            uint8_t x = (uint8_t) (block[i] ^ zb[i]);

            if (decrypting) {
                block[i] = x;
            }
            out[i] = x;
        }
        upd_e_bytes(&m, block);
    }

    encode_lengths(theta, total_ad, total_msg);
    upd_e_bytes(&m, theta);

    c.n0 = m.e0;
    c.n1 = m.e1;
    c.s0 = m.e2;
    c.s1 = m.e3;
    c.s2 = m.e4;
    c.s3 = m.e5;
    scinit(&c, k, variant);

    AES_BLOCK_STORE(tag, scout(&c, variant).lo);
}

static void
aead_dispatch(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *ad, size_t ad_len,
              const uint8_t *key, const uint8_t *iv, uint8_t tag[LOL2D_TAG_BYTES], int decrypting,
              lol2d_lfsr variant)
{
    if (variant == LOL2D_LFSR1) {
        if (decrypting) {
            aead(out, in, len, ad, ad_len, key, iv, tag, 1, LOL2D_LFSR1);
        } else {
            aead(out, in, len, ad, ad_len, key, iv, tag, 0, LOL2D_LFSR1);
        }
    } else {
        if (decrypting) {
            aead(out, in, len, ad, ad_len, key, iv, tag, 1, LOL2D_LFSR2);
        } else {
            aead(out, in, len, ad, ad_len, key, iv, tag, 0, LOL2D_LFSR2);
        }
    }
}

void
lol2d_aead_encrypt(uint8_t *ct, uint8_t tag[LOL2D_TAG_BYTES], const uint8_t *msg, size_t msg_len,
                   const uint8_t *ad, size_t ad_len, const uint8_t *key, const uint8_t *iv,
                   lol2d_lfsr variant)
{
    aead_dispatch(ct, msg, msg_len, ad, ad_len, key, iv, tag, 0, variant);
}

int
lol2d_aead_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len,
                   const uint8_t tag[LOL2D_TAG_BYTES], const uint8_t *ad, size_t ad_len,
                   const uint8_t *key, const uint8_t *iv, lol2d_lfsr variant)
{
    uint8_t  expected[LOL2D_TAG_BYTES];
    uint8_t  computed[LOL2D_TAG_BYTES];
    unsigned diff = 0;
    size_t   i;

    memcpy(expected, tag, LOL2D_TAG_BYTES);

    aead_dispatch(msg, ct, ct_len, ad, ad_len, key, iv, computed, 1, variant);

    for (i = 0; i < LOL2D_TAG_BYTES; i++) {
        diff |= (unsigned) (computed[i] ^ expected[i]);
    }
    if (diff != 0) {
        memset(msg, 0, ct_len);
        return -1;
    }
    return 0;
}
