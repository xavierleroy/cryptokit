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

/* Stub code for the system-provided RNG */

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>

#ifdef _WIN32

/* Inspired by Mike Lin's port of Cryptokit 1.0 */

#define _WIN32_WINNT 0x0400
#include <windows.h>
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
  raise_not_found();
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
