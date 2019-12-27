/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Gallium, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2013 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id: stubs-sha1.c 53 2010-08-30 10:53:00Z gildor-admin $ */

#include <string.h>
#include "keccak.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>

#define Context_val(v) (*((struct SHA3Context **) Data_custom_val(v)))

static void caml_sha3_finalize(value ctx)
{
  if (Context_val(ctx) != NULL) {
    caml_stat_free(Context_val(ctx));
    Context_val(ctx) = NULL;
  }
}

static struct custom_operations SHA3_context_ops = {
  "fr.inria.caml.cryptokit.SHA3_context",
  caml_sha3_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_deserialize_default,
  custom_compare_ext_default
};

CAMLprim value caml_sha3_init(value vsize)
{
  struct SHA3Context * ctx = caml_stat_alloc(sizeof(struct SHA3Context));
  value res =
    caml_alloc_custom(&SHA3_context_ops,
                      sizeof(struct SHA3Context *),
                      0, 1);
  SHA3_init(ctx, Int_val(vsize));
  Context_val(res) = ctx;
  return res;
}

CAMLprim value caml_sha3_absorb(value ctx,
                                value src, value ofs, value len)
{
  SHA3_absorb(Context_val(ctx), &Byte_u(src, Long_val(ofs)), Long_val(len));
  return Val_unit;
}


/* On page 9 of Keccak Implementation Overview (Version 3.2)
   http://keccak.noekeon.org/Keccak-implementation-3.2.pdf,
   there is a figure `0x01` as the padding byte. */
static const unsigned keccak_padding = 0x01;

/* In a similar, updated description at http://keccak.noekeon.org/specs_summary.html,
   on Table 3, `0x06` is shown as the relevant padding byte. */
static const unsigned sha3_padding = 0x06;

CAMLprim value caml_sha3_extract(value official, value ctx)
{
  CAMLparam2(official, ctx);
  CAMLlocal1(res);

  res = caml_alloc_string(Context_val(ctx)->hsiz);
  SHA3_extract(Bool_val(official) ? sha3_padding : keccak_padding, Context_val(ctx), &Byte_u(res, 0));
  CAMLreturn(res);
}

CAMLprim value caml_sha3_wipe(value ctx)
{
  if (Context_val(ctx) != NULL) {
    memset(Context_val(ctx), 0, sizeof(struct SHA3Context));
    caml_stat_free(Context_val(ctx));
    Context_val(ctx) = NULL;
  }
  return Val_unit;
}

