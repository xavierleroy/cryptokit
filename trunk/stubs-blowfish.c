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

/* Stub code for Blowfish */

#include "blowfish.h"
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>

#define CTX_VAL(v) ((BLOWFISH_CTX *) String_val(v))

CAMLprim value caml_blowfish_cook_key(value key)
{
  CAMLparam1(key);
  value ckey = alloc_string(sizeof(BLOWFISH_CTX));
  Blowfish_Init(CTX_VAL(ckey), &Byte_u(key, 0), string_length(key));
  CAMLreturn(ckey);
}

#define Load_ulong(s,ofs) \
  ((Byte_u(s,ofs) << 24) \
  | (Byte_u(s,ofs+1) << 16) \
  | (Byte_u(s,ofs+2) << 8) \
  | Byte_u(s,ofs+3))
#define Store_ulong(x,d,ofs) \
  Byte_u(d,ofs) = x >> 24, \
  Byte_u(d,ofs+1) = x >> 16, \
  Byte_u(d,ofs+2) = x >> 8, \
  Byte_u(d,ofs+3) = x

/*
#define Load_ulong(s,ofs) \
  (Byte_u(s,ofs) | \
  | (Byte_u(s,ofs+1) << 8) \
  | (Byte_u(s,ofs+2) << 16) \
  | (Byte_u(s,ofs+3) << 24))
#define Store_ulong(x,d,ofs) \
  Byte_u(d,ofs) = x, \
  Byte_u(d,ofs+1) = x >> 8, \
  Byte_u(d,ofs+2) = x >> 16, \
  Byte_u(d,ofs+3) = x >> 24
*/

CAMLprim value caml_blowfish_encrypt(value ckey, value src, value src_ofs,
                                     value dst, value dst_ofs)
{
  long sofs = Long_val(src_ofs);
  long dofs = Long_val(dst_ofs);
  unsigned long l = Load_ulong(src, sofs);
  unsigned long h = Load_ulong(src, sofs + 4);
  Blowfish_Encrypt(CTX_VAL(ckey), &l, &h);
  Store_ulong(l, dst, dofs);
  Store_ulong(h, dst, dofs + 4);
  return Val_unit;
}

CAMLprim value caml_blowfish_decrypt(value ckey, value src, value src_ofs,
                                     value dst, value dst_ofs)
{
  long sofs = Long_val(src_ofs);
  long dofs = Long_val(dst_ofs);
  unsigned long l = Load_ulong(src, sofs);
  unsigned long h = Load_ulong(src, sofs + 4);
  Blowfish_Decrypt(CTX_VAL(ckey), &l, &h);
  Store_ulong(l, dst, dofs);
  Store_ulong(h, dst, dofs + 4);
  return Val_unit;
}

