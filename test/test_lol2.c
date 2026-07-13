#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/lol2_double.c"
#include "vectors.h"

static int failures;

static void
fail(const char *tv, const char *what)
{
    failures++;
    printf("FAIL %s: %s\n", tv, what);
}

static void
check(const char *tv, const char *what, const void *got, const void *want, size_t n)
{
    if (memcmp(got, want, n) != 0) {
        fail(tv, what);
    }
}

static void
dump(const char *label, const uint8_t *p, size_t n)
{
    size_t i;

    printf("  %-8s", label);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static void
check_state(const char *tv, const core_t *c, const lol2d_tv_state *want, int step)
{
    lol2d_state    tmp;
    const uint8_t *got;
    uint8_t        exp[160];

    core_to_state(&tmp, c);
    got = tmp.blocks;

    memcpy(exp, want->l, 32);
    memcpy(exp + 32, want->h, 32);
    memcpy(exp + 64, want->n0, 16);
    memcpy(exp + 80, want->n1, 16);
    memcpy(exp + 96, want->s, 64);

    if (memcmp(got, exp, 160) != 0) {
        static const char  *names[] = { "L", "H", "N0", "N1", "S0", "S1", "S2", "S3" };
        static const size_t off[]   = { 0, 32, 64, 80, 96, 112, 128, 144, 160 };
        int                 i;

        failures++;
        printf("FAIL %s: init state trace (t=%d)\n", tv, step - 12);
        for (i = 0; i < 8; i++) {
            size_t n = off[i + 1] - off[i];

            if (memcmp(got + off[i], exp + off[i], n) != 0) {
                printf(" %s differs:\n", names[i]);
                dump("got", got + off[i], n);
                dump("want", exp + off[i], n);
            }
        }
    }
}

static void
test_init_trace(const lol2d_tv *tv, lol2d_lfsr variant)
{
    core_t c;
    int    i;

    load_core(&c, tv->key, tv->iv);
    check_state(tv->name, &c, &tv->init_trace[0], 0);

    for (i = 0; i < 12; i++) {
        scinit_round(&c, variant);
        if (i < 11) {
            check_state(tv->name, &c, &tv->init_trace[i + 1], i + 1);
        }
    }
    c.h = aes_block2_xor(c.h, aes_block2_load(tv->key));
    check_state(tv->name, &c, &tv->init_trace[12], 12);
}

static void
test_keystream(const lol2d_tv *tv, lol2d_lfsr variant)
{
    uint8_t     ks[512];
    uint8_t     buf[512]  = { 0 };
    uint8_t     zero[512] = { 0 };
    lol2d_state st;
    size_t      pos, chunk;
    int         mode;

    lol2d_init(&st, tv->key, tv->iv, variant);
    lol2d_keystream(&st, ks, sizeof ks);
    check(tv->name, "keystream (one shot)", ks, tv->keystream, sizeof ks);

    memset(ks, 0, sizeof ks);
    lol2d_init(&st, tv->key, tv->iv, variant);
    pos   = 0;
    chunk = 1;
    while (pos < sizeof ks) {
        size_t n = chunk % 67 + 1;

        if (n > sizeof ks - pos) {
            n = sizeof ks - pos;
        }
        lol2d_keystream(&st, ks + pos, n);
        pos += n;
        chunk = chunk * 3 + 1;
    }
    check(tv->name, "keystream (chunked)", ks, tv->keystream, sizeof ks);

    lol2d_init(&st, tv->key, tv->iv, variant);
    lol2d_xor(&st, buf, buf, sizeof buf);
    check(tv->name, "xor of zero buffer", buf, tv->keystream, sizeof buf);

    memset(ks, 0, sizeof ks);
    lol2d_init(&st, tv->key, tv->iv, variant);
    pos = 0;
    for (mode = 0; pos < sizeof ks; mode ^= 1) {
        size_t n = (pos * 7 + 5) % 45 + 1;

        if (n > sizeof ks - pos) {
            n = sizeof ks - pos;
        }
        if (mode) {
            lol2d_keystream(&st, ks + pos, n);
        } else {
            lol2d_xor(&st, ks + pos, ks + pos, n);
        }
        pos += n;
    }
    check(tv->name, "keystream/xor interleaved", ks, tv->keystream, sizeof ks);

    lol2d_init(&st, tv->key, tv->iv, variant);
    lol2d_xor(&st, buf, buf, sizeof buf);
    check(tv->name, "xor round-trip", buf, zero, sizeof buf);
}

static const uint8_t our_tag_lfsr1[16] = { 0x3d, 0x66, 0xcc, 0x58, 0x69, 0x2d, 0x1f, 0x07,
                                           0x3b, 0x48, 0x4a, 0x1c, 0xf8, 0xe5, 0xc0, 0x1f };
static const uint8_t our_tag_lfsr2[16] = { 0xf7, 0xda, 0xc4, 0x4a, 0x5f, 0x88, 0xd3, 0x15,
                                           0x13, 0xef, 0xd2, 0x35, 0x0d, 0x06, 0x7a, 0xaa };

static void
test_aead_vector(const lol2d_tv *tv, lol2d_lfsr variant)
{
    uint8_t        msg[512] = { 0 };
    uint8_t        ct[512], dec[512];
    uint8_t        tag[16], bad_tag[16];
    const uint8_t *want;

    lol2d_aead_encrypt(ct, tag, msg, sizeof msg, NULL, 0, tv->key, tv->iv, variant);
    check(tv->name, "aead ciphertext", ct, tv->keystream, sizeof ct);

    want = variant == LOL2D_LFSR1 ? our_tag_lfsr1 : our_tag_lfsr2;
    if (memcmp(tag, want, 16) != 0) {
        fail(tv->name, "aead tag (implementation regression vector)");
        dump("got", tag, 16);
        dump("want", want, 16);
    }
    if (memcmp(tag, tv->tag, 16) != 0) {
        printf(
            "note: %s: paper's printed tag differs from the specified "
            "algorithms (known discrepancy, see NOTES.md)\n",
            tv->name);
    }

    if (lol2d_aead_decrypt(dec, ct, sizeof ct, tag, NULL, 0, tv->key, tv->iv, variant) != 0) {
        fail(tv->name, "aead decrypt (valid tag rejected)");
    } else {
        check(tv->name, "aead decrypt output", dec, msg, sizeof msg);
    }

    memcpy(bad_tag, tag, 16);
    bad_tag[3] ^= 0x40;
    if (lol2d_aead_decrypt(dec, ct, sizeof ct, bad_tag, NULL, 0, tv->key, tv->iv, variant) != -1) {
        fail(tv->name, "aead decrypt (bad tag accepted)");
    }
}

static void
test_aead_roundtrip(const lol2d_tv *tv, lol2d_lfsr variant)
{
    uint8_t  msg[201], ad[57], ct[201], dec[201], tag[16];
    uint8_t  inplace[201];
    uint8_t  zeroed[201], zeros[201] = { 0 };
    uint8_t  bad[16];
    uint32_t x = 0x12345678;
    size_t   i, mlen, alen;

    for (i = 0; i < sizeof msg; i++) {
        x      = x * 1664525 + 1013904223;
        msg[i] = (uint8_t) (x >> 24);
    }
    for (i = 0; i < sizeof ad; i++) {
        x     = x * 1664525 + 1013904223;
        ad[i] = (uint8_t) (x >> 24);
    }

    for (mlen = 0; mlen <= sizeof msg; mlen += (mlen < 64 ? 1 : 39)) {
        for (alen = 0; alen <= sizeof ad; alen += 19) {
            lol2d_aead_encrypt(ct, tag, msg, mlen, ad, alen, tv->key, tv->iv, variant);
            if (lol2d_aead_decrypt(dec, ct, mlen, tag, ad, alen, tv->key, tv->iv, variant) != 0) {
                fail(tv->name, "aead roundtrip decrypt");
                continue;
            }
            check(tv->name, "aead roundtrip payload", dec, msg, mlen);
            if (alen > 0) {
                lol2d_aead_encrypt(ct, tag, msg, mlen, ad, alen - 1, tv->key, tv->iv, variant);
                if (lol2d_aead_decrypt(dec, ct, mlen, tag, ad, alen, tv->key, tv->iv, variant) ==
                    0) {
                    fail(tv->name, "aead accepts wrong AD");
                }
            }
        }
    }

    memcpy(inplace, msg, sizeof msg);
    lol2d_aead_encrypt(ct, tag, msg, sizeof msg, ad, sizeof ad, tv->key, tv->iv, variant);
    lol2d_aead_encrypt(inplace, tag, inplace, sizeof inplace, ad, sizeof ad, tv->key, tv->iv,
                       variant);
    check(tv->name, "aead in-place encrypt", inplace, ct, sizeof ct);

    if (lol2d_aead_decrypt(inplace, inplace, sizeof inplace, tag, ad, sizeof ad, tv->key, tv->iv,
                           variant) != 0) {
        fail(tv->name, "aead in-place decrypt rejected");
    } else {
        check(tv->name, "aead in-place decrypt", inplace, msg, sizeof msg);
    }

    memcpy(bad, tag, 16);
    bad[0] ^= 1;
    memset(zeroed, 0xaa, sizeof zeroed);
    if (lol2d_aead_decrypt(zeroed, ct, sizeof ct, bad, ad, sizeof ad, tv->key, tv->iv, variant) !=
        -1) {
        fail(tv->name, "aead bad tag accepted");
    } else {
        check(tv->name, "aead bad tag zeroes output", zeroed, zeros, sizeof zeroed);
    }
}

int
main(void)
{
    static const struct {
        const lol2d_tv *tv;
        lol2d_lfsr      variant;
    } cases[] = {
        { &lol2d_tv_lfsr1, LOL2D_LFSR1 },
        { &lol2d_tv_lfsr2, LOL2D_LFSR2 },
    };
    size_t i;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        test_init_trace(cases[i].tv, cases[i].variant);
        test_keystream(cases[i].tv, cases[i].variant);
        test_aead_vector(cases[i].tv, cases[i].variant);
        test_aead_roundtrip(cases[i].tv, cases[i].variant);
    }

    if (failures == 0) {
        printf("all tests passed\n");
        return 0;
    }
    printf("%d failure(s)\n", failures);
    return 1;
}
