/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2004 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

#include "sha256.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define Context_val(v) ((struct SHA256Context *) String_val(v))

CAMLprim value caml_sha256_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct SHA256Context));
  SHA256_init(Context_val(ctx), 256);
  return ctx;
}

CAMLprim value caml_sha224_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct SHA256Context));
  SHA256_init(Context_val(ctx), 224);
  return ctx;
}

CAMLprim value caml_sha256_update(value ctx, value src, value ofs, value len)
{
  SHA256_add_data(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_sha256_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(32);
  SHA256_finish(Context_val(ctx), 256, &Byte_u(res, 0));
  CAMLreturn(res);
}

CAMLprim value caml_sha224_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(28);
  SHA256_finish(Context_val(ctx), 224, &Byte_u(res, 0));
  CAMLreturn(res);
}


