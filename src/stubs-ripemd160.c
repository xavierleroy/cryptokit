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

#include "ripemd160.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define Context_val(v) ((struct RIPEMD160Context *) String_val(v))

CAMLprim value caml_ripemd160_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct RIPEMD160Context));
  RIPEMD160_init(Context_val(ctx));
  return ctx;
}

CAMLprim value caml_ripemd160_update(value ctx, value src, value ofs, value len)
{
  RIPEMD160_add_data(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_ripemd160_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(20);
  RIPEMD160_finish(Context_val(ctx), &Byte_u(res, 0));
  CAMLreturn(res);
}

