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

CAMLprim value caml_xor_string(value src, value src_ofs,
                               value dst, value dst_ofs,
                               value len)
{
  char * s = &Byte(src, Long_val(src_ofs));
  char * d = &Byte(dst, Long_val(dst_ofs));
  long l = Long_val(len);

  while (l >= sizeof(long)) {
    *((long *) d) ^= *((long *) s);
    s += sizeof(long);
    d += sizeof(long);
    l -= sizeof(long);
  }
  while (l > 0) {
    *d ^= *s;
    s += 1;
    d += 1;
    l -= 1;
  }
  return Val_unit;
}

  
