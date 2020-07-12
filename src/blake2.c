/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright 2020 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* BLAKE2 hashing */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "blake2.h"

static const uint8_t BLAKE2_sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

/* BLAKE2b */

static inline uint64_t U8TO64LE(unsigned char * src)
{
  return (uint64_t) src[0]         | ((uint64_t) src[1] << 8)
       | ((uint64_t) src[2] << 16) | ((uint64_t) src[3] << 24)
       | ((uint64_t) src[4] << 32) | ((uint64_t) src[5] << 40)
       | ((uint64_t) src[6] << 48) | ((uint64_t) src[7] << 56);
}

static inline uint64_t ROTR64(uint64_t x, int amount)
{
  return (x >> amount) | (x << (64 - amount));
}

static const uint64_t blake2b_iv[8] = {
  UINT64_C(0x6a09e667f3bcc908),
  UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b),
  UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1),
  UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b),
  UINT64_C(0x5be0cd19137e2179)
};

#define MIX2B(a,b,c,d,x,y)                                                  \
  do {                                                                      \
    a += b + x;                                                             \
    d = ROTR64(d ^ a, 32);                                                  \
    c += d;                                                                 \
    b = ROTR64(b ^ c, 24);                                                  \
    a += b + y;                                                             \
    d = ROTR64(d ^ a, 16);                                                  \
    c += d;                                                                 \
    b = ROTR64(b ^ c, 63);                                                  \
  } while(0)                                                                \

static void blake2b_compress(struct blake2b * s, unsigned char * data,
                             unsigned int numbytes, int is_last_block)
{
  uint64_t v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
  uint64_t m[16];
  int i;
  const uint8_t * sigma;

  /* Update the length */
  s->len[0] += numbytes;
  if (s->len[0] < numbytes) s->len[1]++; /* carry */
  /* Initialize work space */
  v0 = s->h[0];  v1 = s->h[1];
  v2 = s->h[2];  v3 = s->h[3];
  v4 = s->h[4];  v5 = s->h[5];
  v6 = s->h[6];  v7 = s->h[7];
  v8 = blake2b_iv[0];  v9 = blake2b_iv[1];
  v10 = blake2b_iv[2]; v11 = blake2b_iv[3];
  v12 = blake2b_iv[4] ^ s->len[0];
  v13 = blake2b_iv[5] ^ s->len[1];
  v14 = is_last_block ? ~ blake2b_iv[6] : blake2b_iv[6];
  v15 = blake2b_iv[7];
  /* Convert data to 16 64-bit words */
  for (i = 0; i < 16; i++) {
    m[i] = U8TO64LE(data + i * 8);
  }
  /* Twelve rounds of mixing */
  for (i = 0; i < 12; i++) {
    sigma = BLAKE2_sigma[i];
    MIX2B(v0, v4, v8,  v12, m[sigma[0]], m[sigma[1]]);
    MIX2B(v1, v5, v9,  v13, m[sigma[2]], m[sigma[3]]);
    MIX2B(v2, v6, v10, v14, m[sigma[4]], m[sigma[5]]);
    MIX2B(v3, v7, v11, v15, m[sigma[6]], m[sigma[7]]);
    MIX2B(v0, v5, v10, v15, m[sigma[8]],  m[sigma[9]]);
    MIX2B(v1, v6, v11, v12, m[sigma[10]], m[sigma[11]]);
    MIX2B(v2, v7, v8,  v13, m[sigma[12]], m[sigma[13]]);
    MIX2B(v3, v4, v9,  v14, m[sigma[14]], m[sigma[15]]);
  }
  /* Update state  */
  s->h[0] ^= v0 ^ v8;   s->h[1] ^= v1 ^ v9;
  s->h[2] ^= v2 ^ v10;  s->h[3] ^= v3 ^ v11;
  s->h[4] ^= v4 ^ v12;  s->h[5] ^= v5 ^ v13;
  s->h[6] ^= v6 ^ v14;  s->h[7] ^= v7 ^ v15;
}

void blake2b_init(struct blake2b * s,
                  int hashlen, int keylen, unsigned char * key)
{
  int i;
  assert (0 < hashlen && hashlen <= 64);
  assert (0 <= keylen && keylen <= 64);
  for (i = 0; i < 8; i++) s->h[i] = blake2b_iv[i];
  s->h[0] ^= 0x01010000 | (keylen << 8) | hashlen;
  s->len[0] = s->len[1] = 0;
  s->numbytes = 0;
  /* If key was supplied, pad to 128 bytes and prepend to message */
  if (keylen > 0) {
    memset(s->buffer, 0, BLAKE2b_BLOCKSIZE);
    memcpy(s->buffer, key, keylen);
    s->numbytes = BLAKE2b_BLOCKSIZE;
  }
}

void blake2b_add_data(struct blake2b * s,
                      unsigned char * data, size_t len)
{
  int n;
  /* If data was left in buffer, pad it with fresh data and compress */
  if (s->numbytes > 0) {
    n = BLAKE2b_BLOCKSIZE - s->numbytes;
    if (len <= n) {
      /* Not enough fresh data to compress.  Buffer the data. */
      memcpy(s->buffer + s->numbytes, data, len);
      s->numbytes += len;
      return;
    }
    memcpy(s->buffer + s->numbytes, data, n);
    blake2b_compress(s, s->buffer, BLAKE2b_BLOCKSIZE, 0);
    data += n; len -= n;
  }
  /* Process data by blocks of BLAKE2b_BLOCKSIZE */
  while (len > BLAKE2b_BLOCKSIZE) {
    blake2b_compress(s, data, BLAKE2b_BLOCKSIZE, 0);
    data += BLAKE2b_BLOCKSIZE; len -= BLAKE2b_BLOCKSIZE;
  }
  /* Save remaining data */
  memcpy(s->buffer, data, len);
  s->numbytes = len;
}

void blake2b_final(struct blake2b * s, int hashlen, unsigned char * hash)
{
  unsigned int i;
  assert (0 < hashlen && hashlen <= 64);
  /* The final block is composed of the remaining data padded with zeros. */
  memset(s->buffer + s->numbytes, 0, BLAKE2b_BLOCKSIZE - s->numbytes);
  blake2b_compress(s, s->buffer, s->numbytes, 1);
  /* Extract the hash */
  for (i = 0; i < hashlen; i++) {
    hash[i] = s->h[i / 8] >> (8 * (i % 8));
  }
}

/* BLAKE2s */

static inline uint32_t U8TO32LE(unsigned char * src)
{
  return (uint32_t) src[0]         | ((uint32_t) src[1] << 8)
       | ((uint32_t) src[2] << 16) | ((uint32_t) src[3] << 24);
}

static inline uint32_t ROTR32(uint32_t x, int amount)
{
  return (x >> amount) | (x << (32 - amount));
}

static const uint32_t blake2s_iv[8] = {
  UINT32_C(0x6A09E667),
  UINT32_C(0xBB67AE85),
  UINT32_C(0x3C6EF372),
  UINT32_C(0xA54FF53A),
  UINT32_C(0x510E527F),
  UINT32_C(0x9B05688C),
  UINT32_C(0x1F83D9AB),
  UINT32_C(0x5BE0CD19)
};

#define MIX2S(a,b,c,d,x,y)                                                  \
  do {                                                                      \
    a += b + x;                                                             \
    d = ROTR32(d ^ a, 16);                                                  \
    c += d;                                                                 \
    b = ROTR32(b ^ c, 12);                                                  \
    a += b + y;                                                             \
    d = ROTR32(d ^ a,  8);                                                  \
    c += d;                                                                 \
    b = ROTR32(b ^ c,  7);                                                  \
  } while(0)                                                                \

static void blake2s_compress(struct blake2s * s, unsigned char * data,
                             unsigned int numbytes, int is_last_block)
{
  uint32_t v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
  uint32_t m[16];
  int i;
  const uint8_t * sigma;

  /* Update the length */
  s->len[0] += numbytes;
  if (s->len[0] < numbytes) s->len[1]++; /* carry */
  /* Initialize work space */
  v0 = s->h[0];  v1 = s->h[1];
  v2 = s->h[2];  v3 = s->h[3];
  v4 = s->h[4];  v5 = s->h[5];
  v6 = s->h[6];  v7 = s->h[7];
  v8 = blake2s_iv[0];  v9 = blake2s_iv[1];
  v10 = blake2s_iv[2]; v11 = blake2s_iv[3];
  v12 = blake2s_iv[4] ^ s->len[0];
  v13 = blake2s_iv[5] ^ s->len[1];
  v14 = is_last_block ? ~ blake2s_iv[6] : blake2s_iv[6];
  v15 = blake2s_iv[7];
  /* Convert data to 16 32-bit words */
  for (i = 0; i < 16; i++) {
    m[i] = U8TO32LE(data + i * 4);
  }
  /* Ten rounds of mixing */
  for (i = 0; i < 10; i++) {
    sigma = BLAKE2_sigma[i];
    MIX2S(v0, v4, v8,  v12, m[sigma[0]], m[sigma[1]]);
    MIX2S(v1, v5, v9,  v13, m[sigma[2]], m[sigma[3]]);
    MIX2S(v2, v6, v10, v14, m[sigma[4]], m[sigma[5]]);
    MIX2S(v3, v7, v11, v15, m[sigma[6]], m[sigma[7]]);
    MIX2S(v0, v5, v10, v15, m[sigma[8]],  m[sigma[9]]);
    MIX2S(v1, v6, v11, v12, m[sigma[10]], m[sigma[11]]);
    MIX2S(v2, v7, v8,  v13, m[sigma[12]], m[sigma[13]]);
    MIX2S(v3, v4, v9,  v14, m[sigma[14]], m[sigma[15]]);
  }
  /* Update state  */
  s->h[0] ^= v0 ^ v8;   s->h[1] ^= v1 ^ v9;
  s->h[2] ^= v2 ^ v10;  s->h[3] ^= v3 ^ v11;
  s->h[4] ^= v4 ^ v12;  s->h[5] ^= v5 ^ v13;
  s->h[6] ^= v6 ^ v14;  s->h[7] ^= v7 ^ v15;
}

void blake2s_init(struct blake2s * s,
                  int hashlen, int keylen, unsigned char * key)
{
  int i;
  assert (0 < hashlen && hashlen <= 32);
  assert (0 <= keylen && keylen <= 32);
  for (i = 0; i < 8; i++) s->h[i] = blake2s_iv[i];
  s->h[0] ^= 0x01010000 | (keylen << 8) | hashlen;
  s->len[0] = s->len[1] = 0;
  s->numbytes = 0;
  /* If key was supplied, pad to 64 bytes and prepend to message */
  if (keylen > 0) {
    memset(s->buffer, 0, BLAKE2s_BLOCKSIZE);
    memcpy(s->buffer, key, keylen);
    s->numbytes = BLAKE2s_BLOCKSIZE;
  }
}

void blake2s_add_data(struct blake2s * s,
                      unsigned char * data, size_t len)
{
  int n;
  /* If data was left in buffer, pad it with fresh data and compress */
  if (s->numbytes > 0) {
    n = BLAKE2s_BLOCKSIZE - s->numbytes;
    if (len <= n) {
      /* Not enough fresh data to compress.  Buffer the data. */
      memcpy(s->buffer + s->numbytes, data, len);
      s->numbytes += len;
      return;
    }
    memcpy(s->buffer + s->numbytes, data, n);
    blake2s_compress(s, s->buffer, BLAKE2s_BLOCKSIZE, 0);
    data += n; len -= n;
  }
  /* Process data by blocks of BLAKE2s_BLOCKSIZE */
  while (len > BLAKE2s_BLOCKSIZE) {
    blake2s_compress(s, data, BLAKE2s_BLOCKSIZE, 0);
    data += BLAKE2s_BLOCKSIZE; len -= BLAKE2s_BLOCKSIZE;
  }
  /* Save remaining data */
  memcpy(s->buffer, data, len);
  s->numbytes = len;
}

void blake2s_final(struct blake2s * s, int hashlen, unsigned char * hash)
{
  unsigned int i;
  assert (0 < hashlen && hashlen <= 32);
  /* The final block is composed of the remaining data padded with zeros. */
  memset(s->buffer + s->numbytes, 0, BLAKE2s_BLOCKSIZE - s->numbytes);
  blake2s_compress(s, s->buffer, s->numbytes, 1);
  /* Extract the hash */
  for (i = 0; i < hashlen; i++) {
    hash[i] = s->h[i / 4] >> (8 * (i % 4));
  }
}
