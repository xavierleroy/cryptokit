/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Gallium, INRIA Paris                */
/*                                                                     */
/*  Copyright 2016 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* Hardware-accelerated implementation of AES */

#include "stdlib.h"
#include "aesni.h"

#ifdef __AES__
#include <wmmintrin.h>
#include <cpuid.h>
#include <stdint.h>

int aesni_available = -1;

int aesni_check_available(void)
{
  unsigned int eax, ebx, ecx, edx;
  if(__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    aesni_available = (ecx & 0x2000000) != 0;
  } else {
    aesni_available = 0;
  }
  return aesni_available;
}

static inline __m128i aesni_128_assist(__m128i t1, __m128i t2)
{
  __m128i t3;
  t2 = _mm_shuffle_epi32 (t2 ,0xff);
  t3 = _mm_slli_si128 (t1, 0x4);
  t1 = _mm_xor_si128 (t1, t3);
  t3 = _mm_slli_si128 (t3, 0x4);
  t1 = _mm_xor_si128 (t1, t3);
  t3 = _mm_slli_si128 (t3, 0x4);
  t1 = _mm_xor_si128 (t1, t3);
  t1 = _mm_xor_si128 (t1, t2);
  return t1;
}

static inline void aesni_192_assist(__m128i * t1, __m128i * t2, __m128i * t3)
{
  __m128i t4;
  *t2 = _mm_shuffle_epi32 (*t2, 0x55);
  t4 = _mm_slli_si128 (*t1, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  *t1 = _mm_xor_si128 (*t1, *t2);
  *t2 = _mm_shuffle_epi32(*t1, 0xff);
  t4 = _mm_slli_si128 (*t3, 0x4);
  *t3 = _mm_xor_si128 (*t3, t4);
  *t3 = _mm_xor_si128 (*t3, *t2);
}

static inline void aesni_256_assist_1(__m128i * t1, __m128i * t2)
{
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0xff);
  t4 = _mm_slli_si128 (*t1, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t1 = _mm_xor_si128 (*t1, t4);
  *t1 = _mm_xor_si128 (*t1, *t2);
}

static inline void aesni_256_assist_2(__m128i * t1, __m128i * t3)
{
  __m128i t2, t4;
  t4 = _mm_aeskeygenassist_si128 (*t1, 0x0);
  t2 = _mm_shuffle_epi32(t4, 0xaa);
  t4 = _mm_slli_si128 (*t3, 0x4);
  *t3 = _mm_xor_si128 (*t3, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t3 = _mm_xor_si128 (*t3, t4);
  t4 = _mm_slli_si128 (t4, 0x4);
  *t3 = _mm_xor_si128 (*t3, t4);
  *t3 = _mm_xor_si128 (*t3, t2);
}

static int aesni_key_expansion(const unsigned char * userkey,
                               int keylength,
                               __m128i * key_schedule)
{
  __m128i t1, t2, t3;
  switch (keylength) {
  case 128:
    t1 = _mm_loadu_si128((__m128i*)userkey);
    key_schedule[0] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1 ,0x1);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[1] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x2);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[2] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x4);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[3] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x8);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[4] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x10);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[5] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x20);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[6] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x40);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[7] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x80);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[8] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x1b);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[9] = t1;
    t2 = _mm_aeskeygenassist_si128 (t1,0x36);
    t1 = aesni_128_assist(t1, t2);
    key_schedule[10] = t1;
    return 10;
  case 192:
    t1 = _mm_loadu_si128((__m128i*)userkey);
    t3 = _mm_loadu_si128((__m128i*)(userkey+16));
    key_schedule[0] = t1;
    key_schedule[1] = t3;
    t2 = _mm_aeskeygenassist_si128 (t3,0x1);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)key_schedule[1],
                                              (__m128d)t1,0);
    key_schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)t1,(__m128d)t3,1);
    t2 = _mm_aeskeygenassist_si128 (t3,0x2);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[3] = t1;
    key_schedule[4] = t3;
    t2 = _mm_aeskeygenassist_si128 (t3,0x4);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)key_schedule[4],
                                              (__m128d)t1,0);
    key_schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)t1,(__m128d)t3,1);
    t2 = _mm_aeskeygenassist_si128 (t3,0x8);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[6] = t1;
    key_schedule[7] = t3;
    t2 = _mm_aeskeygenassist_si128 (t3,0x10);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)key_schedule[7],
                                              (__m128d)t1,0);
    key_schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)t1,(__m128d)t3,1);
    t2 = _mm_aeskeygenassist_si128 (t3,0x20);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[9] = t1;
    key_schedule[10] = t3;
    t2 = _mm_aeskeygenassist_si128 (t3,0x40);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)key_schedule[10],
                                               (__m128d)t1,0);
    key_schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)t1,(__m128d)t3,1);
    t2 = _mm_aeskeygenassist_si128 (t3,0x80);
    aesni_192_assist(&t1, &t2, &t3);
    key_schedule[12] = t1;
    return 12;
  case 256:
    t1 = _mm_loadu_si128((__m128i*)userkey);
    t3 = _mm_loadu_si128((__m128i*)(userkey+16));
    key_schedule[0] = t1;
    key_schedule[1] = t3;
    t2 = _mm_aeskeygenassist_si128 (t3,0x01);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[2] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[3] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x02);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[4] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[5] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x04);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[6] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[7] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x08);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[8] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[9] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x10);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[10] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[11] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x20);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[12] = t1;
    aesni_256_assist_2(&t1, &t3);
    key_schedule[13] = t3;
    t2 = _mm_aeskeygenassist_si128(t3,0x40);
    aesni_256_assist_1(&t1, &t2);
    key_schedule[14] = t1;
    return 14;
  default:
    abort();
  }
}

static void * align16(void * p)
{
  uintptr_t n = (uintptr_t) p;
  n = (n + 15) & -16;
  return (void *) n;
}

int aesniKeySetupEnc(unsigned char * ckey,
                     const unsigned char * key,
                     int keylength)
{
  __m128i unaligned_key_schedule[15 + 1]; /* + 1 to leave space for alignment */
  __m128i *key_schedule = align16(unaligned_key_schedule);
  int nrounds, i;

  nrounds = aesni_key_expansion(key, keylength, key_schedule);
  for (i = 0; i <= nrounds; i++) {
    _mm_storeu_si128((__m128i*) ckey + i, key_schedule[i]);
  }
  return nrounds;
}

int aesniKeySetupDec(unsigned char * ckey,
                     const unsigned char * key,
                     int keylength)
{
  __m128i unaligned_key_schedule[15 + 1]; /* + 1 to leave space for alignment */
  __m128i *key_schedule = align16(unaligned_key_schedule);
  int nrounds, i;

  nrounds = aesni_key_expansion(key, keylength, key_schedule);
  _mm_storeu_si128((__m128i*) ckey + 0, key_schedule[nrounds]);
  for (i = 1; i < nrounds; i++) {
    _mm_storeu_si128((__m128i*) ckey + i,
                     _mm_aesimc_si128(key_schedule[nrounds - i]));
  }
  _mm_storeu_si128((__m128i*) ckey + nrounds, key_schedule[0]);
  return nrounds;
}
                     
void aesniEncrypt(const unsigned char * key, int nrounds,
                  const unsigned char * in,
                  unsigned char * out)
{
  __m128i t, k;
  int j;
  
  t = _mm_loadu_si128 ((__m128i*) in); 
  k = _mm_loadu_si128 ((__m128i*) key + 0);
  t = _mm_xor_si128 (t, k);
  j = 1;
  do {
    k = _mm_loadu_si128 ((__m128i*) key + j);
    t = _mm_aesenc_si128 (t, k);
    j++;
  } while (j < nrounds);
  k = _mm_loadu_si128 ((__m128i*) key + j);
  t = _mm_aesenclast_si128 (t, k);
  _mm_storeu_si128 ((__m128i*) out, t);
}
  
void aesniDecrypt(const unsigned char * key, int nrounds,
                  const unsigned char * in,
                  unsigned char * out)
{
  __m128i t, k;
  int j;
  
  t = _mm_loadu_si128 ((__m128i*) in); 
  k = _mm_loadu_si128 ((__m128i*) key + 0);
  t = _mm_xor_si128 (t, k);
  j = 1;
  do {
    k = _mm_loadu_si128 ((__m128i*) key + j);
    t = _mm_aesdec_si128 (t, k);
    j++;
  } while (j < nrounds);
  k = _mm_loadu_si128 ((__m128i*) key + j);
  t = _mm_aesdeclast_si128 (t, k);
  _mm_storeu_si128 ((__m128i*) out, t);
}
  
#else

int aesni_available = 0;

int aesni_check_available(void) { return 0; }

int aesniKeySetupEnc(unsigned char * ckey,
                     const unsigned char * key,
                     int keylength)
{ abort(); }

int aesniKeySetupDec(unsigned char * ckey,
                     const unsigned char * key,
                     int keylength)
{ abort(); }

void aesniEncrypt(const unsigned char * key, int nrounds,
                  const unsigned char * in,
                  unsigned char * out)
{ abort(); }

void aesniDecrypt(const unsigned char * key, int nrounds,
                  const unsigned char * in,
                  unsigned char * out)
{ abort(); }

#endif

