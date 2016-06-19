/***********************************************************************/
/*                                                                     */
/*                      The Cryptokit library                          */
/*                                                                     */
/*            Xavier Leroy, projet Gallium, INRIA Paris                */
/*                                                                     */
/*  Copyright 2016 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file LICENSE.        */
/*                                                                     */
/***********************************************************************/

/* Hardware-accelerated implementation of AES */

extern int aesni_available;
/* -1: unknown, call aesni_check_available() to determine 
    0: not available
    1: available
*/

extern int aesni_check_available(void);

extern int aesniKeySetupEnc(unsigned char * ckey,
                            const unsigned char * key,
                            int keylength);

extern int aesniKeySetupDec(unsigned char * ckey,
                            const unsigned char * key,
                            int keylength);

extern void aesniEncrypt(const unsigned char * key, int nrounds,
                         const unsigned char * in,
                         unsigned char * out);

extern void aesniDecrypt(const unsigned char * key, int nrounds,
                         const unsigned char * in,
                         unsigned char * out);
    

