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

/* Stub code to interface with Zlib */

#include <zlib.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/memory.h>

#define ZStream_val(v) ((z_stream *) (v))

static value * caml_zlib_error_exn = NULL;

static void caml_zlib_error(char * fn, value vzs)
{
  char * msg;
  value s1 = Val_unit, s2 = Val_unit, tuple = Val_unit, bucket = Val_unit;

  msg = ZStream_val(vzs)->msg;
  if (msg == NULL) msg = "";
  if (caml_zlib_error_exn == NULL) {
    caml_zlib_error_exn = caml_named_value("Cryptokit.Error");
    if (caml_zlib_error_exn == NULL)
      invalid_argument("Exception Cryptokit.Error not initialized");
  }
  Begin_roots4(s1, s2, tuple, bucket);
    s1 = copy_string(fn);
    s2 = copy_string(msg);
    tuple = alloc_small(2, 0);
    Field(tuple, 0) = s1;
    Field(tuple, 1) = s2;
    bucket = alloc_small(2, 0);
    Field(bucket, 0) = *caml_zlib_error_exn;
    Field(bucket, 1) = tuple;
  End_roots();
  mlraise(bucket);
}

static value caml_zlib_new_stream(void)
{
  value res = alloc((sizeof(z_stream) + sizeof(value) - 1) / sizeof(value),
                    Abstract_tag);
  ZStream_val(res)->zalloc = NULL;
  ZStream_val(res)->zfree = NULL;
  ZStream_val(res)->opaque = NULL;
  ZStream_val(res)->next_in = NULL;
  ZStream_val(res)->next_out = NULL;
  return res;
}

CAMLprim
value caml_zlib_deflateInit(value vlevel, value expect_header)
{
  value vzs = caml_zlib_new_stream();
  if (deflateInit2(ZStream_val(vzs),
                   Int_val(vlevel),
                   Z_DEFLATED,
                   Bool_val(expect_header) ? MAX_WBITS : -MAX_WBITS,
                   8,
                   Z_DEFAULT_STRATEGY) != Z_OK)
    caml_zlib_error("Zlib.deflateInit", vzs);
  return vzs;
}

static int caml_zlib_flush_table[] = 
{ Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH };

CAMLprim
value caml_zlib_deflate(value vzs, value srcbuf, value srcpos, value srclen,
                      value dstbuf, value dstpos, value dstlen,
                      value vflush)
{
  z_stream * zs = ZStream_val(vzs);
  int retcode;
  long used_in, used_out;
  value res;

  zs->next_in = &Byte(srcbuf, Long_val(srcpos));
  zs->avail_in = Long_val(srclen);
  zs->next_out = &Byte(dstbuf, Long_val(dstpos));
  zs->avail_out = Long_val(dstlen);
  retcode = deflate(zs, caml_zlib_flush_table[Int_val(vflush)]);
  if (retcode < 0) caml_zlib_error("Zlib.deflate", vzs);
  used_in = Long_val(srclen) - zs->avail_in;
  used_out = Long_val(dstlen) - zs->avail_out;
  zs->next_in = NULL;         /* not required, but cleaner */
  zs->next_out = NULL;        /* (avoid dangling pointers into Caml heap) */
  res = alloc_small(3, 0);
  Field(res, 0) = Val_bool(retcode == Z_STREAM_END);
  Field(res, 1) = Val_int(used_in);
  Field(res, 2) = Val_int(used_out);
  return res;
}

CAMLprim
value caml_zlib_deflate_bytecode(value * arg, int nargs)
{
  return caml_zlib_deflate(arg[0], arg[1], arg[2], arg[3],
                         arg[4], arg[5], arg[6], arg[7]);
}

CAMLprim
value caml_zlib_deflateEnd(value vzs)
{
  if (deflateEnd(ZStream_val(vzs)) != Z_OK)
    caml_zlib_error("Zlib.deflateEnd", vzs);
  return Val_unit;
}

CAMLprim
value caml_zlib_inflateInit(value expect_header)
{
  value vzs = caml_zlib_new_stream();
  if (inflateInit2(ZStream_val(vzs),
                   Bool_val(expect_header) ? MAX_WBITS : -MAX_WBITS) != Z_OK)
    caml_zlib_error("Zlib.inflateInit", vzs);
  return vzs;
}

CAMLprim
value caml_zlib_inflate(value vzs, value srcbuf, value srcpos, value srclen,
                      value dstbuf, value dstpos, value dstlen,
                      value vflush)
{
  z_stream * zs = ZStream_val(vzs);
  int retcode;
  long used_in, used_out;
  value res;

  zs->next_in = &Byte(srcbuf, Long_val(srcpos));
  zs->avail_in = Long_val(srclen);
  zs->next_out = &Byte(dstbuf, Long_val(dstpos));
  zs->avail_out = Long_val(dstlen);
  retcode = inflate(zs, caml_zlib_flush_table[Int_val(vflush)]);
  if (retcode < 0 || retcode == Z_NEED_DICT)
    caml_zlib_error("Zlib.inflate", vzs);
  used_in = Long_val(srclen) - zs->avail_in;
  used_out = Long_val(dstlen) - zs->avail_out;
  zs->next_in = NULL;           /* not required, but cleaner */
  zs->next_out = NULL;          /* (avoid dangling pointers into Caml heap) */
  res = alloc_small(3, 0);
  Field(res, 0) = Val_bool(retcode == Z_STREAM_END);
  Field(res, 1) = Val_int(used_in);
  Field(res, 2) = Val_int(used_out);
  return res;
}

CAMLprim
value caml_zlib_inflate_bytecode(value * arg, int nargs)
{
  return caml_zlib_inflate(arg[0], arg[1], arg[2], arg[3],
                         arg[4], arg[5], arg[6], arg[7]);
}

CAMLprim
value caml_zlib_inflateEnd(value vzs)
{
  if (inflateEnd(ZStream_val(vzs)) != Z_OK)
    caml_zlib_error("Zlib.inflateEnd", vzs);
  return Val_unit;
}

