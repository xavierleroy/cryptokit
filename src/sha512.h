/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         */
/*                                                                     */
/*  Copyright 2015 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* $Id: sha256.h 53 2010-08-30 10:53:00Z gildor-admin $ */

/* SHA-512 hashing */

#ifndef _MSC_VER
#include <stdint.h>
typedef uint64_t u64;
#else
typedef unsigned __int64 u64;
#define UINT64_C(x) x##ui64
#endif

struct SHA512Context {
  u64 state[8];
  u64 length[2];
  int numbytes;
  unsigned char buffer[128];
};

extern void SHA512_init(struct SHA512Context * ctx, int bitsize);
extern void SHA512_add_data(struct SHA512Context * ctx, unsigned char * data,
                            unsigned long len);
extern void SHA512_finish(struct SHA512Context * ctx, int bitsize,
                          unsigned char * output);
