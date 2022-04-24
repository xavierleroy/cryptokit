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

#include "poly1305-donna.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define Context_val(v) ((struct poly1305_context *) String_val(v))

CAMLprim value caml_poly1305_init(value key)
{
  CAMLparam1(key);
  value ctx = caml_alloc_string(sizeof(struct poly1305_context));
  poly1305_init(Context_val(ctx), &Byte_u(key, 0));
  CAMLreturn(ctx);
}

CAMLprim value caml_poly1305_update(value ctx, value src, value ofs, value len)
{
  poly1305_update(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_poly1305_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);
  res = caml_alloc_string(16);
  poly1305_finish(Context_val(ctx), &Byte_u(res, 0));
  CAMLreturn(res);
}

