/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*              Xavier Leroy, Collège de France and Inria              */
/*                                                                     */
/*  Copyright 2020 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* BLAKE2b hashing */

#define BLAKE2b_BLOCKSIZE 128

struct blake2b {
  uint64_t h[8];
  uint64_t len[2];
  int numbytes;
  unsigned char buffer[BLAKE2b_BLOCKSIZE];
};

extern void blake2b_init(struct blake2b * s,
                         int hashlen, int keylen, unsigned char * key);
extern void blake2b_add_data(struct blake2b * s,
                             unsigned char * data, size_t len);
extern void blake2b_final(struct blake2b * s,
                          int hashlen, unsigned char * hash);


