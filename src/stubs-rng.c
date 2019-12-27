/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2003 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* Stub code for the system-provided RNG and for hardware RNG */

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>

/* Win32 system RNG */

#ifdef _WIN32

/* Inspired by Mike Lin's port of Cryptokit 1.0 */

#define _WIN32_WINNT 0x0400
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#ifndef CRYPT_SILENT
#define CRYPT_SILENT 0
#endif

#define HCRYPTPROV_val(v) (*((HCRYPTPROV *) &Field(v, 0)))

CAMLprim value caml_get_system_rng(value unit)
{
  HCRYPTPROV prov;
  value res;

  if (! CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    raise_not_found();
  res = alloc((sizeof(HCRYPTPROV) + sizeof(value) - 1) / sizeof(value),
              Abstract_tag);
  HCRYPTPROV_val(res) = prov;
  return res;
}

CAMLprim value caml_close_system_rng(value vhc)
{
  CryptReleaseContext(HCRYPTPROV_val(vhc), 0);
  return Val_unit;
}

CAMLprim value caml_system_rng_random_bytes(value vhc, value str,
                                            value ofs, value len)
{
  return Val_bool(CryptGenRandom(HCRYPTPROV_val(vhc),
                                 Long_val(len),
                                 &Byte(str, Long_val(ofs))));
}

#else

CAMLprim value caml_get_system_rng(value unit)
{
  caml_raise_not_found();
  return Val_unit;              /* not reached */
}

CAMLprim value caml_close_system_rng(value vhc)
{
  return Val_unit;
}

CAMLprim value caml_system_rng_random_bytes(value vhc, value str,
                                            value ofs, value len)
{
  return Val_false;
}

#endif

/* Intel RDRAND instruction */

#if defined(__GNUC__) && defined(__x86_64)

#include <stdint.h>
#include <string.h>

static inline int rdrand64(uint64_t * res)
{
  uint64_t n;
  unsigned char ok;
  int retries;

  for (retries = 0; retries < 20; retries++) {
    __asm__ __volatile__ ("rdrand %0; setc %1" : "=r" (n), "=qm" (ok));
    if (ok) { *res = n; return 1; }
  }
  return 0;
}

CAMLprim value caml_hardware_rng_available(value unit)
{
  uint32_t ax, bx, cx, dx;
  uint64_t n;
  int retries;
  __asm__ __volatile__ ("cpuid"
                        : "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx)
                        : "a" (1));
  if ((cx & (1U << 30)) == 0) return Val_false;
  /* Early AMD Ryzen 3000 processors have a most annoying bug:
     the rdrand instruction always returns 0xFF....FF.
     We check for this condition here. */
  for (retries = 0; retries < 8; retries++) {
    if (rdrand64(&n) && n != (uint64_t) (-1)) return Val_true;
  }
  /* If we reach here, either rdrand64 failed 8*20=160 times in a row,
     or it returned 8*64=512 "1" bits in a row.  In either case,
     it's unusable. */
  return Val_false;
}

CAMLprim value caml_hardware_rng_random_bytes(value str, value ofs, value len)
{
  unsigned char * dst = &Byte_u(str, Long_val(ofs));
  intnat nbytes = Long_val(len);
  uint64_t r, rr;

  while (nbytes >= 8) {
    if (! rdrand64(&r)) return Val_false;
    *((uint64_t *) dst) = r;
    dst += 8;
    nbytes -= 8;
  }
  if (nbytes > 0) {
    if (! rdrand64(&rr)) return Val_false;
    memcpy(dst, &rr, nbytes);
  }
  return Val_true;
}

#else

CAMLprim value caml_hardware_rng_available(value unit)
{ return Val_false; }

CAMLprim value caml_hardware_rng_random_bytes(value str, value ofs, value len)
{ return Val_false; }

#endif
