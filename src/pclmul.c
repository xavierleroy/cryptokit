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

/* Hardware-accelerated implementation of GHASH multiplication */

#include <stdint.h>
#include <stdlib.h>
#include "pclmul.h"

#ifdef __PCLMUL__

#include <wmmintrin.h>
#include <emmintrin.h>
#include <cpuid.h>

EXPORT int pclmul_available = -1;

EXPORT int pclmul_check_available(void)
{
  unsigned int eax, ebx, ecx, edx;
  if(__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    pclmul_available = (ecx & (1 << 1)) != 0;
  } else {
    pclmul_available = 0;
  }
  return pclmul_available;
}

static void copy_reverse_16(void * dst, const void * src)
{
#define COPY(i) *((uint8_t*) dst + i) = *((const uint8_t *) src + 15 - i)
  COPY(0); COPY(1); COPY(2); COPY(3);
  COPY(4); COPY(5); COPY(6); COPY(7);
  COPY(8); COPY(9); COPY(10); COPY(11);
  COPY(12); COPY(13); COPY(14); COPY(15);
#undef COPY
}

EXPORT void pclmul_mult(uint8_t res[16],
                 const uint8_t arg1[16], const uint8_t arg2[16])
{
  __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

  copy_reverse_16(&tmp0, arg1);
  copy_reverse_16(&tmp1, arg2);

  tmp3 = _mm_clmulepi64_si128(tmp0, tmp1, 0x00);
  tmp4 = _mm_clmulepi64_si128(tmp0, tmp1, 0x10);
  tmp5 = _mm_clmulepi64_si128(tmp0, tmp1, 0x01);
  tmp6 = _mm_clmulepi64_si128(tmp0, tmp1, 0x11);

  tmp4 = _mm_xor_si128(tmp4, tmp5);
  tmp5 = _mm_slli_si128(tmp4, 8);
  tmp4 = _mm_srli_si128(tmp4, 8);
  tmp3 = _mm_xor_si128(tmp3, tmp5);
  tmp6 = _mm_xor_si128(tmp6, tmp4);

  tmp7 = _mm_srli_epi32(tmp3, 31);
  tmp8 = _mm_srli_epi32(tmp6, 31);
  tmp3 = _mm_slli_epi32(tmp3, 1);
  tmp6 = _mm_slli_epi32(tmp6, 1);

  tmp9 = _mm_srli_si128(tmp7, 12);
  tmp8 = _mm_slli_si128(tmp8, 4);
  tmp7 = _mm_slli_si128(tmp7, 4);
  tmp3 = _mm_or_si128(tmp3, tmp7);
  tmp6 = _mm_or_si128(tmp6, tmp8);
  tmp6 = _mm_or_si128(tmp6, tmp9);

  tmp7 = _mm_slli_epi32(tmp3, 31);
  tmp8 = _mm_slli_epi32(tmp3, 30);
  tmp9 = _mm_slli_epi32(tmp3, 25);

  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);
  tmp8 = _mm_srli_si128(tmp7, 4);
  tmp7 = _mm_slli_si128(tmp7, 12);
  tmp3 = _mm_xor_si128(tmp3, tmp7);

  tmp2 = _mm_srli_epi32(tmp3, 1);
  tmp4 = _mm_srli_epi32(tmp3, 2);
  tmp5 = _mm_srli_epi32(tmp3, 7);
  tmp2 = _mm_xor_si128(tmp2, tmp4);
  tmp2 = _mm_xor_si128(tmp2, tmp5);
  tmp2 = _mm_xor_si128(tmp2, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp2);
  tmp6 = _mm_xor_si128(tmp6, tmp3);

  tmp0 = tmp6;
  copy_reverse_16(res, &tmp0);
}

#else

EXPORT int pclmul_available = -1;

EXPORT int pclmul_check_available(void) { return 0; }

EXPORT void pclmul_mult(uint8_t res[16],
                 const uint8_t arg1[16], const uint8_t arg2[16])
{ abort(); }

#endif
