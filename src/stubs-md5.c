/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2002 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#ifndef _MSC_VER
#include <stdint.h>
typedef uint32_t u32;
#else
typedef unsigned int u32;
#endif

struct MD5Context {
        u32 buf[4];
        u32 bits[2];
        unsigned char in[64];
};

CAMLextern void caml_MD5Init (struct MD5Context *context);
CAMLextern void caml_MD5Update (struct MD5Context *context,
                           unsigned char *buf, unsigned len);
CAMLextern void caml_MD5Final (unsigned char *digest, struct MD5Context *ctx);

#define Context_val(v) ((struct MD5Context *) String_val(v))

CAMLprim value caml_md5_init(value unit)
{
  value ctx = caml_alloc_string(sizeof(struct MD5Context));
  caml_MD5Init(Context_val(ctx));
  return ctx;
}

CAMLprim value caml_md5_update(value ctx, value src, value ofs, value len)
{
  caml_MD5Update(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_md5_final(value ctx)
{
  CAMLparam1(ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(16);
  caml_MD5Final(&Byte_u(res, 0), Context_val(ctx));
  CAMLreturn(res);
}

