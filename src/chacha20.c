/* Based on D. J. Bernstein's chacha-regs.c version 200801118,
  https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/regs/chacha.c
  The initial code is in the public domain */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <caml/config.h>
#include "chacha20.h"

static inline void U32TO8_LITTLE(uint8_t * dst, uint32_t val)
{
#ifdef ARCH_BIG_ENDIAN
  dst[0] = val;
  dst[1] = val >> 8;
  dst[2] = val >> 16;
  dst[3] = val >> 24;
#else
  *((uint32_t *) dst) = val;
#endif
}

static inline uint32_t U8TO32_LITTLE(const uint8_t * src)
{
  return (uint32_t) src[0]
    + ((uint32_t) src[1] << 8)
    + ((uint32_t) src[2] << 16)
    + ((uint32_t) src[3] << 24);
}

#define ROTATE(v,c) ((v) << (c) | (v) >> (32 - (c)))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) ((v) + (w))
#define PLUSONE(v) ((v) + 1)

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static void chacha20_block(chacha20_ctx * ctx)
{
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  int i;

  x0 = ctx->input[0];
  x1 = ctx->input[1];
  x2 = ctx->input[2];
  x3 = ctx->input[3];
  x4 = ctx->input[4];
  x5 = ctx->input[5];
  x6 = ctx->input[6];
  x7 = ctx->input[7];
  x8 = ctx->input[8];
  x9 = ctx->input[9];
  x10 = ctx->input[10];
  x11 = ctx->input[11];
  x12 = ctx->input[12];
  x13 = ctx->input[13];
  x14 = ctx->input[14];
  x15 = ctx->input[15];
  for (i = 10; i > 0; i --) {
    QUARTERROUND( x0, x4, x8,x12)
    QUARTERROUND( x1, x5, x9,x13)
    QUARTERROUND( x2, x6,x10,x14)
    QUARTERROUND( x3, x7,x11,x15)
    QUARTERROUND( x0, x5,x10,x15)
    QUARTERROUND( x1, x6,x11,x12)
    QUARTERROUND( x2, x7, x8,x13)
    QUARTERROUND( x3, x4, x9,x14)
  }
  x0 = PLUS(x0,ctx->input[0]);
  x1 = PLUS(x1,ctx->input[1]);
  x2 = PLUS(x2,ctx->input[2]);
  x3 = PLUS(x3,ctx->input[3]);
  x4 = PLUS(x4,ctx->input[4]);
  x5 = PLUS(x5,ctx->input[5]);
  x6 = PLUS(x6,ctx->input[6]);
  x7 = PLUS(x7,ctx->input[7]);
  x8 = PLUS(x8,ctx->input[8]);
  x9 = PLUS(x9,ctx->input[9]);
  x10 = PLUS(x10,ctx->input[10]);
  x11 = PLUS(x11,ctx->input[11]);
  x12 = PLUS(x12,ctx->input[12]);
  x13 = PLUS(x13,ctx->input[13]);
  x14 = PLUS(x14,ctx->input[14]);
  x15 = PLUS(x15,ctx->input[15]);
  U32TO8_LITTLE(ctx->output + 0,x0);
  U32TO8_LITTLE(ctx->output + 4,x1);
  U32TO8_LITTLE(ctx->output + 8,x2);
  U32TO8_LITTLE(ctx->output + 12,x3);
  U32TO8_LITTLE(ctx->output + 16,x4);
  U32TO8_LITTLE(ctx->output + 20,x5);
  U32TO8_LITTLE(ctx->output + 24,x6);
  U32TO8_LITTLE(ctx->output + 28,x7);
  U32TO8_LITTLE(ctx->output + 32,x8);
  U32TO8_LITTLE(ctx->output + 36,x9);
  U32TO8_LITTLE(ctx->output + 40,x10);
  U32TO8_LITTLE(ctx->output + 44,x11);
  U32TO8_LITTLE(ctx->output + 48,x12);
  U32TO8_LITTLE(ctx->output + 52,x13);
  U32TO8_LITTLE(ctx->output + 56,x14);
  U32TO8_LITTLE(ctx->output + 60,x15);
  /* Increment the 64-bit counter and, on overflow, the 64-bit nonce */
  /* (Incrementing the nonce is not standard but a reasonable default.) */
  if (++ ctx->input[12] == 0)
    if (++ ctx->input[13] == 0)
      if (++ ctx->input[14] == 0)
        ++ ctx->input[15];
}

void chacha20_transform(chacha20_ctx * ctx,
                        const uint8_t * in, uint8_t * out, size_t len)
{
  int n = ctx->next;
  for (/*nothing*/; len > 0; len--) {
    if (n >= 64) { chacha20_block(ctx); n = 0; }
    *out++ = *in++ ^ ctx->output[n++];
  }
  ctx->next = n;
}

void chacha20_extract(chacha20_ctx * ctx,
                      uint8_t * out, size_t len)
{
  int n = ctx->next;
  for (/*nothing*/; len > 0; len--) {
    if (n >= 64) { chacha20_block(ctx); n = 0; }
    *out++ = ctx->output[n++];
  }
  ctx->next = n;
}

void chacha20_init(chacha20_ctx * ctx,
                   const uint8_t * key, size_t key_length,
                   const uint8_t iv[8],
                   uint64_t counter)
{
  const uint8_t *constants = 
    (uint8_t *) (key_length == 32 ? "expand 32-byte k" : "expand 16-byte k");
  assert (key_length == 16 || key_length == 32);
  ctx->input[0] = U8TO32_LITTLE(constants + 0);
  ctx->input[1] = U8TO32_LITTLE(constants + 4);
  ctx->input[2] = U8TO32_LITTLE(constants + 8);
  ctx->input[3] = U8TO32_LITTLE(constants + 12);
  ctx->input[4] = U8TO32_LITTLE(key + 0);
  ctx->input[5] = U8TO32_LITTLE(key + 4);
  ctx->input[6] = U8TO32_LITTLE(key + 8);
  ctx->input[7] = U8TO32_LITTLE(key + 12);
  if (key_length == 32) key += 16;
  ctx->input[8] = U8TO32_LITTLE(key + 0);
  ctx->input[9] = U8TO32_LITTLE(key + 4);
  ctx->input[10] = U8TO32_LITTLE(key + 8);
  ctx->input[11] = U8TO32_LITTLE(key + 12);
  ctx->input[12] = (uint32_t) counter;
  ctx->input[13] = (uint32_t) (counter >> 32);
  ctx->input[14] = U8TO32_LITTLE(iv + 0);
  ctx->input[15] = U8TO32_LITTLE(iv + 4);
  ctx->next = 64;
}
