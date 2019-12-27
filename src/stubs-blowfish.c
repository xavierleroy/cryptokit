/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Gallium, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2006 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* Stub code for Blowfish */

#include "blowfish.h"
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>

CAMLprim value caml_blowfish_cook_key(value key)
{
  CAMLparam1(key);
  value ckey = caml_alloc_string(sizeof(BLOWFISH_CTX));
  Blowfish_Init((BLOWFISH_CTX *) String_val(ckey),
                &Byte_u(key, 0),
                caml_string_length(key));
  CAMLreturn(ckey);
}

#ifdef ARCH_BIG_ENDIAN
#define COPY4BYTES(dst,src) \
  (dst)[0] = (src)[0], \
  (dst)[1] = (src)[1], \
  (dst)[2] = (src)[2], \
  (dst)[3] = (src)[3]
#else
#define COPY4BYTES(dst,src) \
  (dst)[0] = (src)[3], \
  (dst)[1] = (src)[2], \
  (dst)[2] = (src)[1], \
  (dst)[3] = (src)[0]
#endif

CAMLprim value caml_blowfish_encrypt(value ckey, value src, value src_ofs,
                                     value dst, value dst_ofs)
{
  u32 xl, xr;
  unsigned char * p;

  p = &Byte_u(src, Long_val(src_ofs));
  COPY4BYTES((unsigned char *) &xl, p);
  COPY4BYTES((unsigned char *) &xr, p + 4);
  Blowfish_Encrypt((BLOWFISH_CTX *) String_val(ckey), &xl, &xr);
  p = &Byte_u(dst, Long_val(dst_ofs));
  COPY4BYTES(p, (unsigned char *) &xl);
  COPY4BYTES(p + 4, (unsigned char *) &xr);
  return Val_unit;
}

CAMLprim value caml_blowfish_decrypt(value ckey, value src, value src_ofs,
                                     value dst, value dst_ofs)
{
  u32 xl, xr;
  unsigned char * p;

  p = &Byte_u(src, Long_val(src_ofs));
  COPY4BYTES((unsigned char *) &xl, p);
  COPY4BYTES((unsigned char *) &xr, p + 4);
  Blowfish_Decrypt((BLOWFISH_CTX *) String_val(ckey), &xl, &xr);
  p = &Byte_u(dst, Long_val(dst_ofs));
  COPY4BYTES(p, (unsigned char *) &xl);
  COPY4BYTES(p + 4, (unsigned char *) &xr);
  return Val_unit;
}

