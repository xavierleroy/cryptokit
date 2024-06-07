/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, Collège de France and Inria                */
/*                                                                     */
/*  Copyright 2022 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

#include <stdint.h>
#include <string.h>
#include "ghash.c"
#include "pclmul.c"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>

#define Context_val(v) (*((struct ghash_context **) Data_custom_val(v)))

static void caml_ghash_finalize(value ctx)
{
  if (Context_val(ctx) != NULL) {
    caml_stat_free(Context_val(ctx));
    Context_val(ctx) = NULL;
  }
}

static struct custom_operations ghash_context_ops = {
  "fr.inria.caml.cryptokit.GHASH_context",
  caml_ghash_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_deserialize_default,
  custom_compare_ext_default
};

CAMLprim value caml_ghash_init(value key)
{
  if (pclmul_available == -1) pclmul_check_available();
  if (pclmul_available == 1) {
    return key;
  } else {
    struct ghash_context * ctx = caml_stat_alloc(sizeof(struct ghash_context));
    value res =
      caml_alloc_custom(&ghash_context_ops,
                        sizeof(struct ghash_context *),
                        0, 1);
    ghash_init(ctx, &Byte_u(key, 0));
    Context_val(res) = ctx;
    return res;
  }
}

CAMLprim value caml_ghash_mult(value ctx, value x)
{
  if (pclmul_available == 1) {
    pclmul_mult(&Byte_u(x, 0), &Byte_u(ctx, 0), &Byte_u(x, 0));
  } else {
    ghash_mult(Context_val(ctx), &Byte_u(x, 0), &Byte_u(x, 0));
  }
  return Val_unit;
}
