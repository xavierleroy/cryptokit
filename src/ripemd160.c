/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2005 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* RIPEMD160 hashing */

#include <string.h>
#include <caml/config.h>
#include "ripemd160.h"

/* Refs:
   - The reference implementation written by Antoon Bosselaers, 
     available at http://www.esat.kuleuven.ac.be/~cosicart/ps/AB-9601/
   - Handbook of Applied Cryptography, section 9.4.2, algorithm 9.55
*/

/* Rotation n bits to the left */
#define ROL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

/* The five basic functions */
#define F(x,y,z) ((x) ^ (y) ^ (z)) 
#define G(x,y,z) (((x) & (y)) | (~(x) & (z))) 
#define H(x,y,z) (((x) | ~(y)) ^ (z))
#define I(x,y,z) (((x) & (z)) | ((y) & ~(z))) 
#define J(x,y,z) ((x) ^ ((y) | ~(z)))
  
/* The ten "steps" for the rounds */
#define FF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x5a827999U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define II(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcU;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0xa953fd4eU;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define FFF(a, b, c, d, e, x, s)        {\
      (a) += F((b), (c), (d)) + (x);\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define GGG(a, b, c, d, e, x, s)        {\
      (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define HHH(a, b, c, d, e, x, s)        {\
      (a) += H((b), (c), (d)) + (x) + 0x6d703ef3U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define III(a, b, c, d, e, x, s)        {\
      (a) += I((b), (c), (d)) + (x) + 0x5c4dd124U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }
#define JJJ(a, b, c, d, e, x, s)        {\
      (a) += J((b), (c), (d)) + (x) + 0x50a28be6U;\
      (a) = ROL((a), (s)) + (e);\
      (c) = ROL((c), 10);\
   }

static void RIPEMD160_copy_and_swap(void * src, void * dst, int numwords)
{
#ifdef ARCH_BIG_ENDIAN
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
#else
  memcpy(dst, src, numwords * sizeof(u32));
#endif
}

static void RIPEMD160_compress(struct RIPEMD160Context * ctx)
{
  register u32 a, b, c, d, e;
  u32 aa, bb, cc, dd, ee;
  u32 data[16];

  /* Convert buffer data to 16 little-endian integers */
  RIPEMD160_copy_and_swap(ctx->buffer, data, 16);

  /* Perform "left" rounds */
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  /* left round 1 */
  FF(a, b, c, d, e, data[ 0], 11);
  FF(e, a, b, c, d, data[ 1], 14);
  FF(d, e, a, b, c, data[ 2], 15);
  FF(c, d, e, a, b, data[ 3], 12);
  FF(b, c, d, e, a, data[ 4],  5);
  FF(a, b, c, d, e, data[ 5],  8);
  FF(e, a, b, c, d, data[ 6],  7);
  FF(d, e, a, b, c, data[ 7],  9);
  FF(c, d, e, a, b, data[ 8], 11);
  FF(b, c, d, e, a, data[ 9], 13);
  FF(a, b, c, d, e, data[10], 14);
  FF(e, a, b, c, d, data[11], 15);
  FF(d, e, a, b, c, data[12],  6);
  FF(c, d, e, a, b, data[13],  7);
  FF(b, c, d, e, a, data[14],  9);
  FF(a, b, c, d, e, data[15],  8);
                             
   /* left round 2 */
  GG(e, a, b, c, d, data[ 7],  7);
  GG(d, e, a, b, c, data[ 4],  6);
  GG(c, d, e, a, b, data[13],  8);
  GG(b, c, d, e, a, data[ 1], 13);
  GG(a, b, c, d, e, data[10], 11);
  GG(e, a, b, c, d, data[ 6],  9);
  GG(d, e, a, b, c, data[15],  7);
  GG(c, d, e, a, b, data[ 3], 15);
  GG(b, c, d, e, a, data[12],  7);
  GG(a, b, c, d, e, data[ 0], 12);
  GG(e, a, b, c, d, data[ 9], 15);
  GG(d, e, a, b, c, data[ 5],  9);
  GG(c, d, e, a, b, data[ 2], 11);
  GG(b, c, d, e, a, data[14],  7);
  GG(a, b, c, d, e, data[11], 13);
  GG(e, a, b, c, d, data[ 8], 12);

   /* left round 3 */
  HH(d, e, a, b, c, data[ 3], 11);
  HH(c, d, e, a, b, data[10], 13);
  HH(b, c, d, e, a, data[14],  6);
  HH(a, b, c, d, e, data[ 4],  7);
  HH(e, a, b, c, d, data[ 9], 14);
  HH(d, e, a, b, c, data[15],  9);
  HH(c, d, e, a, b, data[ 8], 13);
  HH(b, c, d, e, a, data[ 1], 15);
  HH(a, b, c, d, e, data[ 2], 14);
  HH(e, a, b, c, d, data[ 7],  8);
  HH(d, e, a, b, c, data[ 0], 13);
  HH(c, d, e, a, b, data[ 6],  6);
  HH(b, c, d, e, a, data[13],  5);
  HH(a, b, c, d, e, data[11], 12);
  HH(e, a, b, c, d, data[ 5],  7);
  HH(d, e, a, b, c, data[12],  5);

   /* left round 4 */
  II(c, d, e, a, b, data[ 1], 11);
  II(b, c, d, e, a, data[ 9], 12);
  II(a, b, c, d, e, data[11], 14);
  II(e, a, b, c, d, data[10], 15);
  II(d, e, a, b, c, data[ 0], 14);
  II(c, d, e, a, b, data[ 8], 15);
  II(b, c, d, e, a, data[12],  9);
  II(a, b, c, d, e, data[ 4],  8);
  II(e, a, b, c, d, data[13],  9);
  II(d, e, a, b, c, data[ 3], 14);
  II(c, d, e, a, b, data[ 7],  5);
  II(b, c, d, e, a, data[15],  6);
  II(a, b, c, d, e, data[14],  8);
  II(e, a, b, c, d, data[ 5],  6);
  II(d, e, a, b, c, data[ 6],  5);
  II(c, d, e, a, b, data[ 2], 12);

   /* left round 5 */
  JJ(b, c, d, e, a, data[ 4],  9);
  JJ(a, b, c, d, e, data[ 0], 15);
  JJ(e, a, b, c, d, data[ 5],  5);
  JJ(d, e, a, b, c, data[ 9], 11);
  JJ(c, d, e, a, b, data[ 7],  6);
  JJ(b, c, d, e, a, data[12],  8);
  JJ(a, b, c, d, e, data[ 2], 13);
  JJ(e, a, b, c, d, data[10], 12);
  JJ(d, e, a, b, c, data[14],  5);
  JJ(c, d, e, a, b, data[ 1], 12);
  JJ(b, c, d, e, a, data[ 3], 13);
  JJ(a, b, c, d, e, data[ 8], 14);
  JJ(e, a, b, c, d, data[11], 11);
  JJ(d, e, a, b, c, data[ 6],  8);
  JJ(c, d, e, a, b, data[15],  5);
  JJ(b, c, d, e, a, data[13],  6);

  /* Save result of left rounds */
  aa = a; bb = b; cc = c; dd = d; ee = e;

  /* Perform "right" rounds */
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  /* right round 1 */
  JJJ(a, b, c, d, e, data[ 5],  8);
  JJJ(e, a, b, c, d, data[14],  9);
  JJJ(d, e, a, b, c, data[ 7],  9);
  JJJ(c, d, e, a, b, data[ 0], 11);
  JJJ(b, c, d, e, a, data[ 9], 13);
  JJJ(a, b, c, d, e, data[ 2], 15);
  JJJ(e, a, b, c, d, data[11], 15);
  JJJ(d, e, a, b, c, data[ 4],  5);
  JJJ(c, d, e, a, b, data[13],  7);
  JJJ(b, c, d, e, a, data[ 6],  7);
  JJJ(a, b, c, d, e, data[15],  8);
  JJJ(e, a, b, c, d, data[ 8], 11);
  JJJ(d, e, a, b, c, data[ 1], 14);
  JJJ(c, d, e, a, b, data[10], 14);
  JJJ(b, c, d, e, a, data[ 3], 12);
  JJJ(a, b, c, d, e, data[12],  6);

   /* right round 2 */
  III(e, a, b, c, d, data[ 6],  9); 
  III(d, e, a, b, c, data[11], 13);
  III(c, d, e, a, b, data[ 3], 15);
  III(b, c, d, e, a, data[ 7],  7);
  III(a, b, c, d, e, data[ 0], 12);
  III(e, a, b, c, d, data[13],  8);
  III(d, e, a, b, c, data[ 5],  9);
  III(c, d, e, a, b, data[10], 11);
  III(b, c, d, e, a, data[14],  7);
  III(a, b, c, d, e, data[15],  7);
  III(e, a, b, c, d, data[ 8], 12);
  III(d, e, a, b, c, data[12],  7);
  III(c, d, e, a, b, data[ 4],  6);
  III(b, c, d, e, a, data[ 9], 15);
  III(a, b, c, d, e, data[ 1], 13);
  III(e, a, b, c, d, data[ 2], 11);

   /* right round 3 */
  HHH(d, e, a, b, c, data[15],  9);
  HHH(c, d, e, a, b, data[ 5],  7);
  HHH(b, c, d, e, a, data[ 1], 15);
  HHH(a, b, c, d, e, data[ 3], 11);
  HHH(e, a, b, c, d, data[ 7],  8);
  HHH(d, e, a, b, c, data[14],  6);
  HHH(c, d, e, a, b, data[ 6],  6);
  HHH(b, c, d, e, a, data[ 9], 14);
  HHH(a, b, c, d, e, data[11], 12);
  HHH(e, a, b, c, d, data[ 8], 13);
  HHH(d, e, a, b, c, data[12],  5);
  HHH(c, d, e, a, b, data[ 2], 14);
  HHH(b, c, d, e, a, data[10], 13);
  HHH(a, b, c, d, e, data[ 0], 13);
  HHH(e, a, b, c, d, data[ 4],  7);
  HHH(d, e, a, b, c, data[13],  5);

   /* right round 4 */   
  GGG(c, d, e, a, b, data[ 8], 15);
  GGG(b, c, d, e, a, data[ 6],  5);
  GGG(a, b, c, d, e, data[ 4],  8);
  GGG(e, a, b, c, d, data[ 1], 11);
  GGG(d, e, a, b, c, data[ 3], 14);
  GGG(c, d, e, a, b, data[11], 14);
  GGG(b, c, d, e, a, data[15],  6);
  GGG(a, b, c, d, e, data[ 0], 14);
  GGG(e, a, b, c, d, data[ 5],  6);
  GGG(d, e, a, b, c, data[12],  9);
  GGG(c, d, e, a, b, data[ 2], 12);
  GGG(b, c, d, e, a, data[13],  9);
  GGG(a, b, c, d, e, data[ 9], 12);
  GGG(e, a, b, c, d, data[ 7],  5);
  GGG(d, e, a, b, c, data[10], 15);
  GGG(c, d, e, a, b, data[14],  8);

   /* right round 5 */
  FFF(b, c, d, e, a, data[12] ,  8);
  FFF(a, b, c, d, e, data[15] ,  5);
  FFF(e, a, b, c, d, data[10] , 12);
  FFF(d, e, a, b, c, data[ 4] ,  9);
  FFF(c, d, e, a, b, data[ 1] , 12);
  FFF(b, c, d, e, a, data[ 5] ,  5);
  FFF(a, b, c, d, e, data[ 8] , 14);
  FFF(e, a, b, c, d, data[ 7] ,  6);
  FFF(d, e, a, b, c, data[ 6] ,  8);
  FFF(c, d, e, a, b, data[ 2] , 13);
  FFF(b, c, d, e, a, data[13] ,  6);
  FFF(a, b, c, d, e, data[14] ,  5);
  FFF(e, a, b, c, d, data[ 0] , 15);
  FFF(d, e, a, b, c, data[ 3] , 13);
  FFF(c, d, e, a, b, data[ 9] , 11);
  FFF(b, c, d, e, a, data[11] , 11);

  /* Update chaining values */
  d += cc + ctx->state[1];
  ctx->state[1] = ctx->state[2] + dd + e;
  ctx->state[2] = ctx->state[3] + ee + a;
  ctx->state[3] = ctx->state[4] + aa + b;
  ctx->state[4] = ctx->state[0] + bb + c;
  ctx->state[0] = d;
}

void RIPEMD160_init(struct RIPEMD160Context * ctx)
{
  ctx->state[0] = 0x67452301U;
  ctx->state[1] = 0xEFCDAB89U;
  ctx->state[2] = 0x98BADCFEU;
  ctx->state[3] = 0x10325476U;
  ctx->state[4] = 0xC3D2E1F0U;
  ctx->numbytes = 0;
  ctx->length[0] = 0;
  ctx->length[1] = 0;
}

void RIPEMD160_add_data(struct RIPEMD160Context * ctx, unsigned char * data,
                        unsigned long len)
{
  u32 t;

  /* Update length */
  t = ctx->length[0];
  if ((ctx->length[0] = t + (u32) (len << 3)) < t)
    ctx->length[1]++;    /* carry from low 32 bits to high 32 bits */
  ctx->length[1] += (u32) (len >> 29);

  /* If data was left in buffer, pad it with fresh data and munge block */
  if (ctx->numbytes != 0) {
    t = 64 - ctx->numbytes;
    if (len < t) {
      memcpy(ctx->buffer + ctx->numbytes, data, len);
      ctx->numbytes += len;
      return;
    }
    memcpy(ctx->buffer + ctx->numbytes, data, t);
    RIPEMD160_compress(ctx);
    data += t;
    len -= t;
  }
  /* Munge data in 64-byte chunks */
  while (len >= 64) {
    memcpy(ctx->buffer, data, 64);
    RIPEMD160_compress(ctx);
    data += 64;
    len -= 64;
  }
  /* Save remaining data */
  memcpy(ctx->buffer, data, len);
  ctx->numbytes = len;
}

void RIPEMD160_finish(struct RIPEMD160Context * ctx, unsigned char output[20])
{
  int i = ctx->numbytes;

  /* Set first char of padding to 0x80. There is always room. */
  ctx->buffer[i++] = 0x80;
  /* If we do not have room for the length (8 bytes), pad to 64 bytes
     with zeroes and munge the data block */
  if (i > 56) {
    memset(ctx->buffer + i, 0, 64 - i);
    RIPEMD160_compress(ctx);
    i = 0;
  }
  /* Pad to byte 56 with zeroes */
  memset(ctx->buffer + i, 0, 56 - i);
  /* Add length in little-endian */
  RIPEMD160_copy_and_swap(ctx->length, ctx->buffer + 56, 2);
  /* Munge the final block */
  RIPEMD160_compress(ctx);
  /* Final hash value is in ctx->state modulo little-endian conversion */
  RIPEMD160_copy_and_swap(ctx->state, output, 5);
}
