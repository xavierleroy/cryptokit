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

/* Software implementation of GHASH multiplication */

struct ghash_context {
    uint64_t HL[16];        // precalculated lo-half HTable
    uint64_t HH[16];        // precalculated hi-half HTable
};

EXPORT void ghash_init(struct ghash_context * ctx,
                       const uint8_t h[16]);

EXPORT void ghash_mult(const struct ghash_context * ctx,
                       const uint8_t input[16],
                       uint8_t output[16]);
