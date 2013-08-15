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

/* SHA-1 hashing */

typedef unsigned int u32;

struct SHA1Context {
  u32 state[5];
  u32 length[2];
  int numbytes;
  unsigned char buffer[64];
};

extern void SHA1_init(struct SHA1Context * ctx);
extern void SHA1_add_data(struct SHA1Context * ctx, unsigned char * data,
                          unsigned long len);
extern void SHA1_finish(struct SHA1Context * ctx, unsigned char output[20]);
