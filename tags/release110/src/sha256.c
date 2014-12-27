/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2004 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* SHA-256 hashing */

#include <string.h>
#include <caml/config.h>
#include "sha256.h"

/* Ref: FIPS publication 180-2 */

#define ROTR(x,n) ((x) >> (n) | (x) << (32 - (n)))

#define CH(x,y,z) (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define SIGMA0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define SIGMA1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

static void SHA256_copy_and_swap(void * src, void * dst, int numwords)
{
#ifdef ARCH_BIG_ENDIAN
  memcpy(dst, src, numwords * sizeof(u32));
#else
  unsigned char * s, * d;
  unsigned char a, b;
  for (s = src, d = dst; numwords > 0; s += 4, d += 4, numwords--) {
    a = s[0];
    b = s[1];
    d[0] = s[3];
    d[1] = s[2];
    d[2] = b;
    d[3] = a;
  }
#endif
}

static u32 SHA256_constants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void SHA256_transform(struct SHA256Context * ctx)
{
  int i;
  register u32 a, b, c, d, e, f, g, h, t1, t2;
  u32 data[80];

  /* Convert buffer data to 16 big-endian integers */
  SHA256_copy_and_swap(ctx->buffer, data, 16);

  /* Expand into 80 integers */
  for (i = 16; i < 80; i++) {
    data[i] = sigma1(data[i-2]) + data[i-7] + sigma0(data[i-15]) + data[i-16];
  }

  /* Initialize working variables */
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  /* Perform rounds */
#if 0
  for (i = 0; i < 64; i++) {
    t1 = h + SIGMA1(e) + CH(e, f, g) + SHA256_constants[i] + data[i];
    t2 = SIGMA0(a) + MAJ(a, b, c);
    h = g;  g = f;  f = e;  e = d + t1;
    d = c;  c = b;  b = a;  a = t1 + t2;
  }
#else
#define STEP(a,b,c,d,e,f,g,h,i) \
    t1 = h + SIGMA1(e) + CH(e, f, g) + SHA256_constants[i] + data[i]; \
    t2 = SIGMA0(a) + MAJ(a, b, c); \
    d = d + t1; \
    h = t1 + t2

  for (i = 0; i < 64; i += 8) {
    STEP(a,b,c,d,e,f,g,h,i);
    STEP(h,a,b,c,d,e,f,g,i+1);
    STEP(g,h,a,b,c,d,e,f,i+2);
    STEP(f,g,h,a,b,c,d,e,i+3);
    STEP(e,f,g,h,a,b,c,d,i+4);
    STEP(d,e,f,g,h,a,b,c,i+5);
    STEP(c,d,e,f,g,h,a,b,i+6);
    STEP(b,c,d,e,f,g,h,a,i+7);
  }
#endif

  /* Update chaining values */
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void SHA256_init(struct SHA256Context * ctx, int bitsize)
{
  switch (bitsize) {
  case 224:
    ctx->state[0] = 0xc1059ed8;
    ctx->state[1] = 0x367cd507;
    ctx->state[2] = 0x3070dd17;
    ctx->state[3] = 0xf70e5939;
    ctx->state[4] = 0xffc00b31;
    ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64f98fa7;
    ctx->state[7] = 0xbefa4fa4;
    break;
  case 256:
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
    break;
  default:
    /* The bit size is wrong.  Just zero the state to produce 
       incorrect hashes. */
    memset(ctx->state, 0, sizeof(ctx->state));
    break;
  }
  ctx->numbytes = 0;
  ctx->length[0] = 0;
  ctx->length[1] = 0;
}

void SHA256_add_data(struct SHA256Context * ctx, unsigned char * data,
                   unsigned long len)
{
  u32 t;

  /* Update length */
  t = ctx->length[1];
  if ((ctx->length[1] = t + (u32) (len << 3)) < t)
    ctx->length[0]++;    /* carry from low 32 bits to high 32 bits */
  ctx->length[0] += (u32) (len >> 29);

  /* If data was left in buffer, pad it with fresh data and munge block */
  if (ctx->numbytes != 0) {
    t = 64 - ctx->numbytes;
    if (len < t) {
      memcpy(ctx->buffer + ctx->numbytes, data, len);
      ctx->numbytes += len;
      return;
    }
    memcpy(ctx->buffer + ctx->numbytes, data, t);
    SHA256_transform(ctx);
    data += t;
    len -= t;
  }
  /* Munge data in 64-byte chunks */
  while (len >= 64) {
    memcpy(ctx->buffer, data, 64);
    SHA256_transform(ctx);
    data += 64;
    len -= 64;
  }
  /* Save remaining data */
  memcpy(ctx->buffer, data, len);
  ctx->numbytes = len;
}

void SHA256_finish(struct SHA256Context * ctx, int bitsize,
                   unsigned char * output)
{
  int i = ctx->numbytes;

  /* Set first char of padding to 0x80. There is always room. */
  ctx->buffer[i++] = 0x80;
  /* If we do not have room for the length (8 bytes), pad to 64 bytes
     with zeroes and munge the data block */
  if (i > 56) {
    memset(ctx->buffer + i, 0, 64 - i);
    SHA256_transform(ctx);
    i = 0;
  }
  /* Pad to byte 56 with zeroes */
  memset(ctx->buffer + i, 0, 56 - i);
  /* Add length in big-endian */
  SHA256_copy_and_swap(ctx->length, ctx->buffer + 56, 2);
  /* Munge the final block */
  SHA256_transform(ctx);
  /* Final hash value is in ctx->state modulo big-endian conversion */
  switch (bitsize) {
  case 256:
    SHA256_copy_and_swap(ctx->state, output, 8);
    break;
  case 224:
    SHA256_copy_and_swap(ctx->state, output, 7);
    break;
  /* default: The bit size is wrong.  Produce no output. */
  }
}
