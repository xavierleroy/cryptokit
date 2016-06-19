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

#include <string.h>
#include <caml/mlvalues.h>

#define ALIGNMENT_OF(x) ((long)(x) & (sizeof(long) - 1))

CAMLprim value caml_xor_string(value src, value src_ofs,
                               value dst, value dst_ofs,
                               value len)
{
  char * s = &Byte(src, Long_val(src_ofs));
  char * d = &Byte(dst, Long_val(dst_ofs));
  long l = Long_val(len);

  if (l >= 64 && ALIGNMENT_OF(s) == ALIGNMENT_OF(d)) {
    while (ALIGNMENT_OF(s) != 0 && l > 0) {
      *d ^= *s;
      s += 1;
      d += 1;
      l -= 1;
    }
    while (l >= sizeof(long)) {
      *((long *) d) ^= *((long *) s);
      s += sizeof(long);
      d += sizeof(long);
      l -= sizeof(long);
    }
  }
  while (l > 0) {
    *d ^= *s;
    s += 1;
    d += 1;
    l -= 1;
  }
  return Val_unit;
}

CAMLprim value caml_wipe_z(value v)
{
  if (Is_block(v) && Tag_val(v) == Custom_tag) {
    memset(Data_custom_val(v), 0, (Wosize_val(v) - 1) * sizeof(value));
  }
  return Val_unit;
}
