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

#include "arcfour.h"

void arcfour_cook_key(struct arcfour_key * key,
                      unsigned char * key_data,
                      int key_data_len)
{
  unsigned char * s;
  int i;
  unsigned char t, index1, index2;

  s = &key->state[0];
  for (i = 0; i < 256; i++) s[i] = i;
  key->x = 0;
  key->y = 0;
  index1 = 0;
  index2 = 0;
  for (i = 0; i < 256; i++) {
    index2 = key_data[index1] + s[i] + index2;
    t = s[i]; s[i] = s[index2]; s[index2] = t;
    index1++;
    if (index1 >= key_data_len) index1 = 0;
  }
}

void arcfour_encrypt(struct arcfour_key * key,
                     char * src, char * dst, long len)
{
  int x, y, kx, ky;

  x = key->x;
  y = key->y;
  for (/*nothing*/; len > 0; len--) {
    x = (x + 1) & 0xFF;
    kx = key->state[x];
    y = (kx + y) & 0xFF;
    ky = key->state[y];
    key->state[x] = ky; key->state[y] = kx;
    *dst++ = *src++ ^ key->state[(kx + ky) & 0xFF];
  }
  key->x = x;
  key->y = y;
}
  

