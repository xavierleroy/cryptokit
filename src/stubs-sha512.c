/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2015 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id: stubs-sha256.c 53 2010-08-30 10:53:00Z gildor-admin $ */

#include "sha512.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define Context_val(v) ((struct SHA512Context *) String_val(v))

CAMLprim value caml_sha512_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct SHA512Context));
  SHA512_init(Context_val(ctx), 512);
  return ctx;
}

CAMLprim value caml_sha384_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct SHA512Context));
  SHA512_init(Context_val(ctx), 384);
  return ctx;
}

CAMLprim value caml_sha512_update(value ctx, value src, value ofs, value len)
{
  SHA512_add_data(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_sha512_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(64);
  SHA512_finish(Context_val(ctx), 512, &Byte_u(res, 0));
  CAMLreturn(res);
}

CAMLprim value caml_sha384_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(48);
  SHA512_finish(Context_val(ctx), 384, &Byte_u(res, 0));
  CAMLreturn(res);
}

