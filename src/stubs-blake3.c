/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright 2022 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

#include <stdint.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include "blake3.h"

#define Context_val(v) (*((blake3_hasher **) Data_custom_val(v)))

static void caml_blake3_finalize(value ctx)
{
  if (Context_val(ctx) != NULL) {
    caml_stat_free(Context_val(ctx));
    Context_val(ctx) = NULL;
  }
}

static struct custom_operations blake3_context_ops = {
  "fr.inria.caml.cryptokit.blake3_context",
  caml_blake3_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_deserialize_default,
  custom_compare_ext_default
};

CAMLprim value caml_blake3_init(value optkey)
{
  CAMLparam1(optkey);
  blake3_hasher * ctx = caml_stat_alloc(sizeof(blake3_hasher));
  value res =
    caml_alloc_custom(&blake3_context_ops,
                      sizeof(blake3_hasher *),
                      0, 1);
  if (caml_string_length(optkey) == BLAKE3_KEY_LEN) {
    blake3_hasher_init_keyed(ctx, &Byte_u(optkey, 0));
  } else {
    blake3_hasher_init(ctx);
  }
  Context_val(res) = ctx;
  CAMLreturn(res);
}

CAMLprim value caml_blake3_update(value ctx,
                                  value src, value ofs, value len)
{
  blake3_hasher_update(Context_val(ctx),
                       &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}


CAMLprim value caml_blake3_extract(value ctx, value vlen)
{
  CAMLparam2(ctx, vlen);
  CAMLlocal1(res);
  size_t len = Long_val(vlen);
  res = caml_alloc_string(len);
  blake3_hasher_finalize(Context_val(ctx), &Byte_u(res, 0), len);
  CAMLreturn(res);
}

CAMLprim value caml_blake3_wipe(value ctx)
{
  if (Context_val(ctx) != NULL)
    memset(Context_val(ctx), 0, sizeof(blake3_hasher));
  caml_blake3_finalize(ctx);
  return Val_unit;
}

