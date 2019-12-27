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

/* Stub code for ARC4 */

#include "arcfour.h"
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>

#define Cooked_key_size (sizeof(struct arcfour_key))
#define Key_val(v) ((struct arcfour_key *) String_val(v))

CAMLprim value caml_arcfour_cook_key(value key)
{
  CAMLparam1(key);
  value ckey = caml_alloc_string(Cooked_key_size);
  arcfour_cook_key(Key_val(ckey),
                   (unsigned char *) String_val(key),
                   caml_string_length(key));
  CAMLreturn(ckey);
}

CAMLprim value caml_arcfour_transform(value ckey, value src, value src_ofs,
                                      value dst, value dst_ofs, value len)
{
  arcfour_encrypt(Key_val(ckey),
                  &Byte(src, Long_val(src_ofs)),
                  &Byte(dst, Long_val(dst_ofs)),
                  Long_val(len));
  return Val_unit;
}

CAMLprim value caml_arcfour_transform_bytecode(value * argv, int argc)
{
  return caml_arcfour_transform(argv[0], argv[1], argv[2],
                                argv[3], argv[4], argv[5]);
}
