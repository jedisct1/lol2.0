#include <stdio.h>
#include <string.h>

#include "../src/backend.h"

typedef struct {
    aes_block_t l, h, n, s0, s1, s2;
} mini_t;

static void
mini_lambda(const uint8_t in[16], uint8_t out[16])
{
    uint16_t w[8], o[8];
    int      i;

    for (i = 0; i < 8; i++) {
        w[i] = (uint16_t) (in[2 * i] | (in[2 * i + 1] << 8));
    }
    for (i = 0; i < 8; i++) {
        if (i == 0 || i == 3 || i == 4) {
            o[i] = (uint16_t) (w[i] >> 6);
        } else if (i & 1) {
            o[i] = (uint16_t) ((w[i] << 5) ^ (w[i - 1] >> 11));
        } else {
            o[i] = (uint16_t) (w[i] << 5);
        }
    }
    for (i = 0; i < 8; i++) {
        out[2 * i]     = (uint8_t) o[i];
        out[2 * i + 1] = (uint8_t) (o[i] >> 8);
    }
}

static aes_block_t
mini_f(aes_block_t h, aes_block_t l)
{
    static const uint8_t perm[16] = { 2, 3, 4, 5, 14, 15, 8, 9, 12, 13, 6, 7, 0, 1, 10, 11 };
    uint8_t              hb[16], lb[16], f[16];
    int                  i;

    AES_BLOCK_STORE(hb, h);
    AES_BLOCK_STORE(lb, l);
    mini_lambda(hb, f);
    for (i = 0; i < 16; i++) {
        f[i] ^= lb[perm[i]];
    }
    return AES_BLOCK_LOAD(f);
}

static aes_block_t
mini_scout(mini_t *c)
{
    aes_block_t g = AES_ENC(c->s2, c->n);
    aes_block_t f = mini_f(c->h, c->l);
    aes_block_t z = AES_ENC(g, c->n);
    aes_block_t t1, t2;

    c->n  = AES_ENC(c->n, c->l);
    c->l  = c->h;
    c->h  = f;
    t2    = AES_ENC(c->s1, c->s2);
    t1    = AES_ENC(c->s0, c->s1);
    c->s0 = AES_BLOCK_XOR(c->s0, AES_BLOCK_XOR(f, g));
    c->s2 = t2;
    c->s1 = t1;
    return z;
}

static void
mini_scinit(mini_t *c, aes_block_t kh, aes_block_t kl)
{
    int i;

    for (i = 0; i < 12; i++) {
        aes_block_t z = mini_scout(c);

        c->h = AES_BLOCK_XOR(c->h, z);
        c->n = AES_BLOCK_XOR(c->n, z);
    }
    c->h  = AES_BLOCK_XOR(c->h, kh);
    c->s0 = AES_BLOCK_XOR(c->s0, kl);
}

typedef struct {
    aes_block_t e[4];
} mini_mac;

static void
mini_upd(mini_mac *m, aes_block_t d)
{
    aes_block_t u = AES_ENC(m->e[3], m->e[0]);

    m->e[3] = AES_ENC(m->e[2], m->e[3]);
    m->e[2] = AES_ENC(m->e[1], m->e[2]);
    m->e[1] = AES_ENC(m->e[0], m->e[1]);
    m->e[0] = AES_BLOCK_XOR(u, d);
}

static const uint8_t tv_key[32] = { 0x27, 0x85, 0x15, 0x1d, 0x94, 0xc4, 0x19, 0x31,
                                    0xad, 0x58, 0x93, 0x32, 0x2b, 0xc0, 0x16, 0x4e,
                                    0x9b, 0xf5, 0x49, 0x63, 0xde, 0xdf, 0x68, 0x87,
                                    0xaa, 0xdc, 0xc1, 0x81, 0x08, 0x40, 0x38, 0x4e };
static const uint8_t tv_iv[16]  = { 0x26, 0xf6, 0x97, 0xad, 0xd2, 0xdd, 0x76, 0x39,
                                    0xf1, 0xb5, 0xf0, 0x97, 0x19, 0xd1, 0xfd, 0x8e };
static const uint8_t tv_h0[16]  = { 0x6d, 0xc9, 0x2b, 0xc3, 0xaf, 0x55, 0x19, 0x61,
                                    0x97, 0x15, 0x21, 0x16, 0xdf, 0x99, 0xde, 0xfa };
static const uint8_t tv_ks0[16] = { 0x67, 0x5f, 0x88, 0x56, 0x3a, 0x37, 0x6a, 0xbd,
                                    0x69, 0x42, 0xa2, 0xdb, 0x0a, 0xa5, 0x9d, 0x57 };
static const uint8_t tv_tag[16] = { 0x3c, 0x88, 0x05, 0xda, 0x77, 0xd3, 0x2c, 0x06,
                                    0xcd, 0xa1, 0x64, 0x51, 0x8a, 0x2d, 0x47, 0xb8 };

int
main(void)
{
    int         failures = 0;
    aes_block_t kl       = AES_BLOCK_LOAD(tv_key);
    aes_block_t kh       = AES_BLOCK_LOAD(tv_key + 16);
    uint8_t     got[16];
    mini_t      c;
    mini_mac    m;
    aes_block_t z;
    uint8_t     theta[16] = { 0 };
    uint64_t    msg_bits  = 2048;
    int         i;

    c.l  = AES_BLOCK_ZERO();
    c.h  = AES_BLOCK_ZERO();
    c.n  = AES_BLOCK_ZERO();
    c.s0 = kh;
    c.s1 = kl;
    c.s2 = AES_BLOCK_LOAD(tv_iv);
    mini_scinit(&c, kh, kl);
    AES_BLOCK_STORE(got, c.h);
    if (memcmp(got, tv_h0, 16) != 0) {
        printf("FAIL mini control: H at t=0\n");
        failures++;
    }

    m.e[0] = c.n;
    m.e[1] = c.s0;
    m.e[2] = c.s1;
    m.e[3] = c.s2;

    z = mini_scout(&c);
    AES_BLOCK_STORE(got, z);
    if (memcmp(got, tv_ks0, 16) != 0) {
        printf("FAIL mini control: keystream block 0\n");
        failures++;
    }
    mini_upd(&m, AES_BLOCK_ZERO());
    for (i = 1; i < 16; i++) {
        mini_scout(&c);
        mini_upd(&m, AES_BLOCK_ZERO());
    }

    for (i = 0; i < 8; i++) {
        theta[8 + i] = (uint8_t) (msg_bits >> (8 * i));
    }
    mini_upd(&m, AES_BLOCK_LOAD(theta));

    c.n  = m.e[0];
    c.s0 = m.e[1];
    c.s1 = m.e[2];
    c.s2 = m.e[3];
    mini_scinit(&c, kh, kl);

    AES_BLOCK_STORE(got, mini_scout(&c));
    if (memcmp(got, tv_tag, 16) != 0) {
        printf("FAIL mini control: SCMAC tag\n");
        failures++;
    }

    if (failures == 0) {
        printf("mini control test passed\n");
        return 0;
    }
    return 1;
}
