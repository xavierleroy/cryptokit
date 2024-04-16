/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright 2022 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

#include <stdint.h>
#include <string.h>
#include "siphash.c"

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define siphash_val(v) ((struct siphash *) String_val(v))

CAMLprim value caml_siphash_init(value key, value hashlen)
{
  value ctx = caml_alloc_string(sizeof(struct siphash));
  siphash_init(siphash_val(ctx), &Byte_u(key, 0), Int_val(hashlen));
  return ctx;
}

CAMLprim value caml_siphash_update(value ctx, value src, value ofs, value len)
{
  siphash_add(siphash_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_siphash_final(value ctx, value hashlen)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);
  int len = Int_val(hashlen);
  res = caml_alloc_string(len);
  siphash_final(siphash_val(ctx), len, &Byte_u(res, 0));
  CAMLreturn(res);
}
