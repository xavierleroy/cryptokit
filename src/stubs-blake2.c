/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright 2020 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

#include <stdint.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include "blake2.h"

#define blake2b_val(v) ((struct blake2b *) String_val(v))

CAMLprim value caml_blake2b_init(value hashlen, value key)
{
  value ctx = caml_alloc_string(sizeof(struct blake2b));
  blake2b_init(blake2b_val(ctx),
               Int_val(hashlen),
               caml_string_length(key), &Byte_u(key, 0));
  return ctx;
}

CAMLprim value caml_blake2b_update(value ctx, value src, value ofs, value len)
{
  blake2b_add_data(blake2b_val(ctx), 
                   &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_blake2b_final(value ctx, value hashlen)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);
  int len = Int_val(hashlen);
  res = caml_alloc_string(len);
  blake2b_final(blake2b_val(ctx), len, &Byte_u(res, 0));
  CAMLreturn(res);
}

#define blake2s_val(v) ((struct blake2s *) String_val(v))

CAMLprim value caml_blake2s_init(value hashlen, value key)
{
  value ctx = caml_alloc_string(sizeof(struct blake2s));
  blake2s_init(blake2s_val(ctx),
               Int_val(hashlen),
               caml_string_length(key), &Byte_u(key, 0));
  return ctx;
}

CAMLprim value caml_blake2s_update(value ctx, value src, value ofs, value len)
{
  blake2s_add_data(blake2s_val(ctx), 
                   &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_blake2s_final(value ctx, value hashlen)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);
  int len = Int_val(hashlen);
  res = caml_alloc_string(len);
  blake2s_final(blake2s_val(ctx), len, &Byte_u(res, 0));
  CAMLreturn(res);
}
