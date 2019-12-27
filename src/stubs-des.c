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

/* Stub code for DES */

#include "d3des.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#define Cooked_key_size (32 * sizeof(u32))

CAMLprim value caml_des_cook_key(value key, value ofs, value direction)
{
  CAMLparam2(key,direction);
  value ckey = caml_alloc_string(Cooked_key_size);
  d3des_cook_key((u8 *) &Byte(key, Long_val(ofs)),
                 Int_val(direction),
                 (u32 *) String_val(ckey));
  CAMLreturn(ckey);
}

CAMLprim value caml_des_transform(value ckey, value src, value src_ofs,
                                  value dst, value dst_ofs)
{
  d3des_transform((u32 *) String_val(ckey),
                  (u8 *) &Byte(src, Long_val(src_ofs)),
                  (u8 *) &Byte(dst, Long_val(dst_ofs)));
  return Val_unit;
}

