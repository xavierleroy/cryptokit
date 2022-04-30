/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright (c) 2012-2016 Jean-Philippe Aumasson                     */
/*  <jeanphilippe.aumasson@gmail.com>                                  */
/*  Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>         */
/*  Copyright 2022 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* Based on the SipHash reference C implementation by Aumasson and Berstein
   https://github.com/veorq/SipHash
   and lightly adapted by Leroy.
   The original implementation is distributed under the CC0 Public Domain
   Dedication. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "siphash.h"

#define ROTL64(x,n) ((x) << n | (x) >> (64-n))

static inline uint64_t U8TO64_LE(const unsigned char *p) {
  return (((uint64_t)(p[0] & 0xff)      ) |
          ((uint64_t)(p[1] & 0xff) <<  8) |
          ((uint64_t)(p[2] & 0xff) << 16) |
          ((uint64_t)(p[3] & 0xff) << 24) |
          ((uint64_t)(p[4] & 0xff) << 32) |
          ((uint64_t)(p[5] & 0xff) << 40) |
          ((uint64_t)(p[6] & 0xff) << 48) |
          ((uint64_t)(p[7] & 0xff) << 56));
}

static inline void U64TO8_LE(unsigned char *p, uint64_t v) {
  p[0] = (v      ) & 0xff;
  p[1] = (v >>  8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
  p[4] = (v >> 32) & 0xff;
  p[5] = (v >> 40) & 0xff;
  p[6] = (v >> 48) & 0xff;
  p[7] = (v >> 56) & 0xff;
}

void siphash_init(struct siphash * st, const unsigned char * key, int outlen)
{
  uint64_t k0 = U8TO64_LE(key);
  uint64_t k1 = U8TO64_LE(key + 8);
  st->v0 = 0x736f6d6570736575;
  st->v1 = 0x646f72616e646f6d;
  st->v2 = 0x6c7967656e657261;
  st->v3 = 0x7465646279746573;
  st->v3 ^= k1;
  st->v2 ^= k0;
  st->v1 ^= k1;
  st->v0 ^= k0;
  if (outlen == 16) st->v1 ^= 0xEE;
  st->used = 0;
  st->len8 = 0;
}

static inline void siphash_round(struct siphash * st)
{
  st->v0 += st->v1;
  st->v1 = ROTL64(st->v1, 13);
  st->v1 ^= st->v0;
  st->v0 = ROTL64(st->v0, 32);
  st->v2 += st->v3;
  st->v3 = ROTL64(st->v3, 16);
  st->v3 ^= st->v2;
  st->v0 += st->v3;
  st->v3 = ROTL64(st->v3, 21);
  st->v3 ^= st->v0;
  st->v2 += st->v1;
  st->v1 = ROTL64(st->v1, 17);
  st->v1 ^= st->v2;
  st->v2 = ROTL64(st->v2, 32);
}

static void siphash_mix(struct siphash * st, uint64_t x)
{
  st->v3 ^= x;
  siphash_round(st);
  siphash_round(st);
  st->v0 ^= x;
}

void siphash_add(struct siphash * st, const unsigned char * p, size_t len)
{
  int used = st->used;
  int free = SIPHASH_BUFLEN - used;

  st->len8 += len;
  if (len < free) {
    memcpy(st->buffer + used, p, len);
    st->used = used + len;
    return;
  }
  if (used > 0) {
    memcpy(st->buffer + used, p, free);
    siphash_mix(st, U8TO64_LE(st->buffer));
    p += free;
    len -= free;
  }
  while (len >= SIPHASH_BUFLEN) {
    siphash_mix(st, U8TO64_LE(p));
    p += SIPHASH_BUFLEN;
    len -= SIPHASH_BUFLEN;
  }
  if (len > 0) memcpy(st->buffer, p, len);
  st->used = len;
}

static uint64_t siphash_final_rounds(struct siphash * st)
{
  /* Four rounds at the end */
  for (int i = 0; i < 4; i++) siphash_round(st);
  /* Fold state down to 64 bits */
  return st->v0 ^ st->v1 ^ st->v2 ^ st->v3;
}

void siphash_final(struct siphash * st, int outlen, unsigned char * out)
{
  uint64_t w;
  /* Finish with the remaining bytes (up to 7 bytes).
     Also use the low 8 bits of the length. */
  w = (uint64_t) st->len8 << 56;
  switch (st->len8 & 7) {
  case 7: w |= (uint64_t) st->buffer[6] << 48;  /* fallthrough */
  case 6: w |= (uint64_t) st->buffer[5] << 40;  /* fallthrough */
  case 5: w |= (uint64_t) st->buffer[4] << 32;  /* fallthrough */
  case 4: w |= (uint64_t) st->buffer[3] << 24;  /* fallthrough */
  case 3: w |= (uint64_t) st->buffer[2] << 16;  /* fallthrough */
  case 2: w |= (uint64_t) st->buffer[1] << 8;   /* fallthrough */
  case 1: w |= (uint64_t) st->buffer[0];        /* fallthrough */
  case 0: /*skip*/;
  }
  siphash_mix(st, w);
  /* First 64 bit of hash */
  st->v2 ^= (outlen == 16 ? 0xEE : 0xFF);
  U64TO8_LE(out, siphash_final_rounds(st));
  /* Next 64 bits of hash, if requested */
  if (outlen == 16) {
    st->v1 ^= 0xDD;
    U64TO8_LE(out + 8, siphash_final_rounds(st));
  }
}

