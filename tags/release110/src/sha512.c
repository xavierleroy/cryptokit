/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2015 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id: sha256.c 53 2010-08-30 10:53:00Z gildor-admin $ */

/* SHA-512 hashing */

#include <string.h>
#include <caml/config.h>
#include "sha512.h"

/* Ref: FIPS publication 180-2 */

#define ROTR(x,n) ((x) >> (n) | (x) << (64 - (n)))

#define CH(x,y,z) (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define SIGMA0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define SIGMA1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x,1) ^ ROTR(x,8) ^ (x >> 7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ (x >> 6))

static void SHA512_copy_and_swap(void * src, void * dst, int numwords)
{
#ifdef ARCH_BIG_ENDIAN
  memcpy(dst, src, numwords * 8);
#else
  unsigned char * s, * d;
  unsigned char a, b;
  for (s = src, d = dst; numwords > 0; s += 8, d += 8, numwords--) {
    a = s[0];
    b = s[1];
    d[0] = s[7];
    d[1] = s[6];
    d[6] = b;
    d[7] = a;
    a = s[2];
    b = s[3];
    d[2] = s[5];
    d[3] = s[4];
    d[4] = b;
    d[5] = a;
  }
#endif
}

static u64 SHA512_constants[80] = {
  UINT64_C(0x428a2f98d728ae22),
  UINT64_C(0x7137449123ef65cd),
  UINT64_C(0xb5c0fbcfec4d3b2f),
  UINT64_C(0xe9b5dba58189dbbc),
  UINT64_C(0x3956c25bf348b538),
  UINT64_C(0x59f111f1b605d019),
  UINT64_C(0x923f82a4af194f9b),
  UINT64_C(0xab1c5ed5da6d8118),
  UINT64_C(0xd807aa98a3030242),
  UINT64_C(0x12835b0145706fbe),
  UINT64_C(0x243185be4ee4b28c),
  UINT64_C(0x550c7dc3d5ffb4e2),
  UINT64_C(0x72be5d74f27b896f),
  UINT64_C(0x80deb1fe3b1696b1),
  UINT64_C(0x9bdc06a725c71235),
  UINT64_C(0xc19bf174cf692694),
  UINT64_C(0xe49b69c19ef14ad2),
  UINT64_C(0xefbe4786384f25e3),
  UINT64_C(0x0fc19dc68b8cd5b5),
  UINT64_C(0x240ca1cc77ac9c65),
  UINT64_C(0x2de92c6f592b0275),
  UINT64_C(0x4a7484aa6ea6e483),
  UINT64_C(0x5cb0a9dcbd41fbd4),
  UINT64_C(0x76f988da831153b5),
  UINT64_C(0x983e5152ee66dfab),
  UINT64_C(0xa831c66d2db43210),
  UINT64_C(0xb00327c898fb213f),
  UINT64_C(0xbf597fc7beef0ee4),
  UINT64_C(0xc6e00bf33da88fc2),
  UINT64_C(0xd5a79147930aa725),
  UINT64_C(0x06ca6351e003826f),
  UINT64_C(0x142929670a0e6e70),
  UINT64_C(0x27b70a8546d22ffc),
  UINT64_C(0x2e1b21385c26c926),
  UINT64_C(0x4d2c6dfc5ac42aed),
  UINT64_C(0x53380d139d95b3df),
  UINT64_C(0x650a73548baf63de),
  UINT64_C(0x766a0abb3c77b2a8),
  UINT64_C(0x81c2c92e47edaee6),
  UINT64_C(0x92722c851482353b),
  UINT64_C(0xa2bfe8a14cf10364),
  UINT64_C(0xa81a664bbc423001),
  UINT64_C(0xc24b8b70d0f89791),
  UINT64_C(0xc76c51a30654be30),
  UINT64_C(0xd192e819d6ef5218),
  UINT64_C(0xd69906245565a910),
  UINT64_C(0xf40e35855771202a),
  UINT64_C(0x106aa07032bbd1b8),
  UINT64_C(0x19a4c116b8d2d0c8),
  UINT64_C(0x1e376c085141ab53),
  UINT64_C(0x2748774cdf8eeb99),
  UINT64_C(0x34b0bcb5e19b48a8),
  UINT64_C(0x391c0cb3c5c95a63),
  UINT64_C(0x4ed8aa4ae3418acb),
  UINT64_C(0x5b9cca4f7763e373),
  UINT64_C(0x682e6ff3d6b2b8a3),
  UINT64_C(0x748f82ee5defb2fc),
  UINT64_C(0x78a5636f43172f60),
  UINT64_C(0x84c87814a1f0ab72),
  UINT64_C(0x8cc702081a6439ec),
  UINT64_C(0x90befffa23631e28),
  UINT64_C(0xa4506cebde82bde9),
  UINT64_C(0xbef9a3f7b2c67915),
  UINT64_C(0xc67178f2e372532b),
  UINT64_C(0xca273eceea26619c),
  UINT64_C(0xd186b8c721c0c207),
  UINT64_C(0xeada7dd6cde0eb1e),
  UINT64_C(0xf57d4f7fee6ed178),
  UINT64_C(0x06f067aa72176fba),
  UINT64_C(0x0a637dc5a2c898a6),
  UINT64_C(0x113f9804bef90dae),
  UINT64_C(0x1b710b35131c471b),
  UINT64_C(0x28db77f523047d84),
  UINT64_C(0x32caab7b40c72493),
  UINT64_C(0x3c9ebe0a15c9bebc),
  UINT64_C(0x431d67c49c100d4c),
  UINT64_C(0x4cc5d4becb3e42b6),
  UINT64_C(0x597f299cfc657e2a),
  UINT64_C(0x5fcb6fab3ad6faec),
  UINT64_C(0x6c44198c4a475817)
};

static void SHA512_transform(struct SHA512Context * ctx)
{
  int i;
  register u64 a, b, c, d, e, f, g, h, t1, t2;
  u64 data[80];

  /* Convert buffer data to 16 big-endian integers */
  SHA512_copy_and_swap(ctx->buffer, data, 16);

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
  for (i = 0; i < 80; i++) {
    t1 = h + SIGMA1(e) + CH(e, f, g) + SHA512_constants[i] + data[i];
    t2 = SIGMA0(a) + MAJ(a, b, c);
    h = g;  g = f;  f = e;  e = d + t1;
    d = c;  c = b;  b = a;  a = t1 + t2;
  }
#else
#define STEP(a,b,c,d,e,f,g,h,i) \
    t1 = h + SIGMA1(e) + CH(e, f, g) + SHA512_constants[i] + data[i]; \
    t2 = SIGMA0(a) + MAJ(a, b, c); \
    d = d + t1; \
    h = t1 + t2

  for (i = 0; i < 80; i += 8) {
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

void SHA512_init(struct SHA512Context * ctx, int bitsize)
{
  switch (bitsize) {
  case 512:
    ctx->state[0] = UINT64_C(0x6a09e667f3bcc908);
    ctx->state[1] = UINT64_C(0xbb67ae8584caa73b);
    ctx->state[2] = UINT64_C(0x3c6ef372fe94f82b);
    ctx->state[3] = UINT64_C(0xa54ff53a5f1d36f1 );
    ctx->state[4] = UINT64_C(0x510e527fade682d1);
    ctx->state[5] = UINT64_C(0x9b05688c2b3e6c1f);
    ctx->state[6] = UINT64_C(0x1f83d9abfb41bd6b);
    ctx->state[7] = UINT64_C(0x5be0cd19137e2179);
    break;
  case 384:
    ctx->state[0] = UINT64_C(0xcbbb9d5dc1059ed8);
    ctx->state[1] = UINT64_C(0x629a292a367cd507);
    ctx->state[2] = UINT64_C(0x9159015a3070dd17);
    ctx->state[3] = UINT64_C(0x152fecd8f70e5939 );
    ctx->state[4] = UINT64_C(0x67332667ffc00b31);
    ctx->state[5] = UINT64_C(0x8eb44a8768581511);
    ctx->state[6] = UINT64_C(0xdb0c2e0d64f98fa7);
    ctx->state[7] = UINT64_C(0x47b5481dbefa4fa4);
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

void SHA512_add_data(struct SHA512Context * ctx, unsigned char * data,
                     unsigned long len)
{
  u64 t;

  /* Update length */
  t = ctx->length[1];
  if ((ctx->length[1] = t + (u64) (len << 3)) < t)
    ctx->length[0]++;    /* carry from low 64 bits to high 64 bits */
  ctx->length[0] += (u64) len >> 61;

  /* If data was left in buffer, pad it with fresh data and munge block */
  if (ctx->numbytes != 0) {
    unsigned long l = 128 - ctx->numbytes;
    if (len < l) {
      memcpy(ctx->buffer + ctx->numbytes, data, len);
      ctx->numbytes += len;
      return;
    }
    memcpy(ctx->buffer + ctx->numbytes, data, l);
    SHA512_transform(ctx);
    data += l;
    len -= l;
  }
  /* Munge data in 128-byte chunks */
  while (len >= 128) {
    memcpy(ctx->buffer, data, 128);
    SHA512_transform(ctx);
    data += 128;
    len -= 128;
  }
  /* Save remaining data */
  memcpy(ctx->buffer, data, len);
  ctx->numbytes = len;
}

void SHA512_finish(struct SHA512Context * ctx, int bitsize,
                   unsigned char * output)
{
  int i = ctx->numbytes;

  /* Set first char of padding to 0x80. There is always room. */
  ctx->buffer[i++] = 0x80;
  /* If we do not have room for the length (8 bytes), pad to 64 bytes
     with zeroes and munge the data block */
  if (i > 112) {
    memset(ctx->buffer + i, 0, 128 - i);
    SHA512_transform(ctx);
    i = 0;
  }
  /* Pad to byte 112 with zeroes */
  memset(ctx->buffer + i, 0, 112 - i);
  /* Add length in big-endian */
  SHA512_copy_and_swap(ctx->length, ctx->buffer + 112, 2);
  /* Munge the final block */
  SHA512_transform(ctx);
  /* Final hash value is in ctx->state modulo big-endian conversion */
  switch (bitsize) {
  case 512:
    SHA512_copy_and_swap(ctx->state, output, 8);
    break;
  case 384:
    SHA512_copy_and_swap(ctx->state, output, 6);
    break;
  /* default: The bit size is wrong.  Produce no output. */
  }
}
