/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, Collège de France and Inria                */
/*                                                                     */
/*  Copyright 2022 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* Software implementation of GHASH multiplication */

/* Based on the implementation by Steven M. Gibson at
   https://github.com/mko-x/SharedAES-GCM/blob/master/Sources/gcm.c
   Gibson's implementation is in the public domain. */

#include <stdint.h>
#include <string.h>
#include "ghash.h"

static inline uint64_t get_uint64_be(const uint8_t * b, int i)
{
  return
      ( (uint64_t) b[i    ] << 56 )
    | ( (uint64_t) b[i + 1] << 48 )
    | ( (uint64_t) b[i + 2] << 40 )
    | ( (uint64_t) b[i + 3] << 32 )
    | ( (uint64_t) b[i + 4] << 24 )
    | ( (uint64_t) b[i + 5] << 16 )
    | ( (uint64_t) b[i + 6] <<  8 )
    | ( (uint64_t) b[i + 7]       );
}

static inline void put_uint64_be(uint64_t n, uint8_t * b, int i)
{
    b[i    ] = n >> 56;
    b[i + 1] = n >> 48;
    b[i + 2] = n >> 40;
    b[i + 3] = n >> 32;
    b[i + 4] = n >> 24;
    b[i + 5] = n >> 16;
    b[i + 6] = n >>  8;
    b[i + 7] = n;
}

void ghash_mult(const struct ghash_context * ctx,
                const uint8_t input[16],
                uint8_t output[16])
{
    static const uint64_t last4[16] = {
        0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
    };
    int i;
    uint8_t lo, hi, rem;
    uint64_t zh, zl;

    lo = (uint8_t)( input[15] & 0x0f );
    hi = (uint8_t)( input[15] >> 4 );
    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for( i = 15; i >= 0; i-- ) {
        lo = (uint8_t) ( input[i] & 0x0f );
        hi = (uint8_t) ( input[i] >> 4 );

        if( i != 15 ) {
            rem = (uint8_t) ( zl & 0x0f );
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];
        }
        rem = (uint8_t) ( zl & 0x0f );
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zh ^= (uint64_t) last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }
    put_uint64_be(zh, output, 0 );
    put_uint64_be(zl, output, 8 );
}

void ghash_init(struct ghash_context * ctx,
                const uint8_t h[16])
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;

    memset(ctx, 0, sizeof(struct ghash_context)); 

    vh = get_uint64_be(h, 0);
    vl = get_uint64_be(h, 8);

    ctx->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
    ctx->HH[8] = vh;
    ctx->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    ctx->HL[0] = 0;

    for( i = 4; i > 0; i >>= 1 ) {
        uint32_t T = (uint32_t) ( vl & 1 ) * 0xe1000000U;
        vl  = ( vh << 63 ) | ( vl >> 1 );
        vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);
        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }
    for (i = 2; i < 16; i <<= 1 ) {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for( j = 1; j < i; j++ ) {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }
}
