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

struct arcfour_key
{      
  unsigned char state[256];       
  unsigned char x, y;
};

extern void arcfour_cook_key(struct arcfour_key * key,
                             unsigned char * key_data,
                             int key_data_len);

extern void arcfour_encrypt(struct arcfour_key * key,
                            char * src, char * dst, long len);

