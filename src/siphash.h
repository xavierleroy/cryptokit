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

#define SIPHASH_BUFLEN 8

struct siphash {
  uint64_t v0, v1, v2, v3;
  unsigned char buffer[SIPHASH_BUFLEN];
  int used;        /* number of valid bytes in buffer */
  uint8_t len8;    /* 8 low bits of total data length */
};

EXPORT void siphash_init(struct siphash * st,
                         const unsigned char * key, int outlen);
EXPORT void siphash_add(struct siphash * st,
                        const unsigned char * p, size_t len);
EXPORT void siphash_final(struct siphash * st,
                          int outlen, unsigned char * out);

