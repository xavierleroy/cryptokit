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

/* Hardware-accelerated implementation of GHASH multiplication */

EXPORT int pclmul_available;
/* -1: unknown, call pclmul_check_available() to determine 
    0: not available
    1: available
*/

EXPORT int pclmul_check_available(void);

EXPORT void pclmul_mult(uint8_t res[16],
                        const uint8_t arg1[16], const uint8_t arg2[16]);


