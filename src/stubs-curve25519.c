/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, Collège de France and Inria                */
/*                                                                     */
/*  Copyright 2025 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

#include "curve25519-donna.c"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

CAMLprim value caml_curve25519_mult(value pt, value n)
{
  value res = caml_alloc_string(CRYPTO_BYTES);
  crypto_scalarmult(&Byte_u(res, 0), &Byte_u(n, 0), &Byte_u(pt, 0));
  return res;
}

CAMLprim value caml_curve25519_basepoint(value vunit)
{
  value res = caml_alloc_string(CRYPTO_BYTES);
  memcpy(&Byte_u(res, 0), crypto_scalarmult_basepoint, CRYPTO_BYTES);
  return res;
}
