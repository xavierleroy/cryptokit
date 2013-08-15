/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2005 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

/* RIPEMD160 hashing */

typedef unsigned int u32;

struct RIPEMD160Context {
  u32 state[5];
  u32 length[2];
  int numbytes;
  unsigned char buffer[64];
};

extern void RIPEMD160_init(struct RIPEMD160Context * ctx);
extern void RIPEMD160_add_data(struct RIPEMD160Context * ctx, 
                               unsigned char * data,
                               unsigned long len);
extern void RIPEMD160_finish(struct RIPEMD160Context * ctx, 
                             unsigned char output[20]);
