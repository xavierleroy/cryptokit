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

/* SHA-256 hashing */

#ifndef _MSC_VER
#include <stdint.h>
typedef uint32_t u32;
#else
typedef unsigned int u32;
#endif

struct SHA256Context {
  u32 state[8];
  u32 length[2];
  int numbytes;
  unsigned char buffer[64];
};

extern void SHA256_init(struct SHA256Context * ctx, int bitsize);
extern void SHA256_add_data(struct SHA256Context * ctx, unsigned char * data,
                            unsigned long len);
extern void SHA256_finish(struct SHA256Context * ctx, 
                          int bitsize,
                          unsigned char * output);
