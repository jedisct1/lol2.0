/* LOL2.0-Double stream cipher and SCMAC AEAD.
 *
 * The API uses byte strings.
 * Paper vectors are printed most-significant byte first, so the supplied arrays are reversed.
 *
 * Never reuse an IV with a key.
 * Keep each stream below the specification's 2^61-byte limit.
 */
#ifndef lol2_H
#define lol2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOL2D_KEY_BYTES 32U
#define LOL2D_IV_BYTES  32U
#define LOL2D_TAG_BYTES 16U

/* LFSR2 is faster.
 * Use LFSR1 only for interoperability.
 */
typedef enum {
    LOL2D_LFSR2 = 0,
    LOL2D_LFSR1 = 1
} lol2d_lfsr;

/* Streaming context.
 * Its contents are private.
 */
typedef struct {
    uint8_t blocks[160];
    uint8_t ks[32];
    uint8_t ks_used;
    uint8_t variant;
} lol2d_state;

/* Initializes a stream with key and IV.
 * Values other than LOL2D_LFSR1 select LFSR2.
 */
void lol2d_init(lol2d_state   *st,
                const uint8_t  key[LOL2D_KEY_BYTES],
                const uint8_t  iv[LOL2D_IV_BYTES],
                lol2d_lfsr     variant);

/* Writes the next n keystream bytes to out. */
void lol2d_keystream(lol2d_state *st,
                     uint8_t     *out,
                     size_t       n);

/* XORs the next n keystream bytes with src into dst.
 * src and dst may be identical but must not otherwise overlap. */
void lol2d_xor(lol2d_state   *st,
               uint8_t       *dst,
               const uint8_t *src,
               size_t         n);

/* Encrypts msg and writes a 128-bit SCMAC tag.
 * msg and ct may be identical but must not otherwise overlap.
 * tag must not overlap another buffer.
 * ad and msg may be NULL when their lengths are zero. */
void lol2d_aead_encrypt(uint8_t       *ct,
                        uint8_t        tag[LOL2D_TAG_BYTES],
                        const uint8_t *msg,
                        size_t         msg_len,
                        const uint8_t *ad,
                        size_t         ad_len,
                        const uint8_t *key,
                        const uint8_t *iv,
                        lol2d_lfsr     variant);

/* Verifies tag and decrypts ct into msg.
 * Returns 0 on success.
 * Otherwise returns -1 and clears msg.
 * The comparison is constant-time.
 *
 * msg and ct may be identical but must not otherwise overlap.
 * msg is written before verification.
 * Use it only when this function returns 0.
 */
int lol2d_aead_decrypt(uint8_t       *msg,
                       const uint8_t *ct,
                       size_t         ct_len,
                       const uint8_t  tag[LOL2D_TAG_BYTES],
                       const uint8_t *ad,
                       size_t         ad_len,
                       const uint8_t *key,
                       const uint8_t *iv,
                       lol2d_lfsr     variant);

#ifdef __cplusplus
}
#endif

#endif
