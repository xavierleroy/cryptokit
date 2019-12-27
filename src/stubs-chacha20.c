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

/* Stub code for Chacha20 */

#include "chacha20.h"
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>

#define Cooked_key_size (sizeof(chacha20_ctx))
#define Key_val(v) ((chacha20_ctx *) String_val(v))

CAMLprim value caml_chacha20_cook_key(value key, value iv, value counter)
{
  CAMLparam2(key, iv);
  value ckey = caml_alloc_string(Cooked_key_size);
  chacha20_init(Key_val(ckey),
                (unsigned char *) String_val(key), caml_string_length(key),
                (unsigned char *) String_val(iv), Int64_val(counter));
  CAMLreturn(ckey);
}

CAMLprim value caml_chacha20_transform(value ckey, value src, value src_ofs,
                                      value dst, value dst_ofs, value len)
{
  chacha20_transform(Key_val(ckey),
                     &Byte_u(src, Long_val(src_ofs)),
                     &Byte_u(dst, Long_val(dst_ofs)),
                     Long_val(len));
  return Val_unit;
}

CAMLprim value caml_chacha20_transform_bytecode(value * argv, int argc)
{
  return caml_chacha20_transform(argv[0], argv[1], argv[2],
                                 argv[3], argv[4], argv[5]);
}

CAMLprim value caml_chacha20_extract(value ckey,
                                     value dst, value dst_ofs, value len)
{
  chacha20_extract(Key_val(ckey),
                   &Byte_u(dst, Long_val(dst_ofs)),
                   Long_val(len));
  return Val_unit;
}

