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

/* Stub code for AES */

#include "rijndael-alg-fst.h"
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>

/* 128-bit key only -> 10 rounds */
#define Num_rounds 10
#define Cooked_key_size ((4 * (Num_rounds + 1)) * sizeof(u32))

CAMLprim value caml_aes_cook_encrypt_key(value key)
{
  CAMLparam1(key);
  value ckey = alloc_string(Cooked_key_size);
  rijndaelKeySetupEnc((u32 *) String_val(ckey),
                      (const u8 *) String_val(key),
                      128);
  CAMLreturn(ckey);
}

CAMLprim value caml_aes_cook_decrypt_key(value key)
{
  CAMLparam1(key);
  value ckey = alloc_string(Cooked_key_size);
  rijndaelKeySetupDec((u32 *) String_val(ckey),
                      (const u8 *) String_val(key),
                      128);
  CAMLreturn(ckey);
}

CAMLprim value caml_aes_encrypt(value ckey, value src, value src_ofs,
                                value dst, value dst_ofs)
{
  rijndaelEncrypt((const u32 *) String_val(ckey),
                  Num_rounds,
                  (const u8 *) &Byte(src, Long_val(src_ofs)),
                  (u8 *) &Byte(dst, Long_val(dst_ofs)));
  return Val_unit;
}

CAMLprim value caml_aes_decrypt(value ckey, value src, value src_ofs,
                                value dst, value dst_ofs)
{
  rijndaelDecrypt((const u32 *) String_val(ckey),
                  Num_rounds,
                  (const u8 *) &Byte(src, Long_val(src_ofs)),
                  (u8 *) &Byte(dst, Long_val(dst_ofs)));
  return Val_unit;
}

