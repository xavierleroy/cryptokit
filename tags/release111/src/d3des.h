/* d3des.h -
 *
 *	Headers and defines for d3des.c
 *	Graven Imagery, 1992.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge
 *	(GEnie : OUTER; CIS : [71755,204])
 *
 * Modified and adapted by Xavier Leroy, 2002.
 */

#define EN0	0	/* MODE == encrypt */
#define DE1	1	/* MODE == decrypt */

typedef unsigned char u8;
typedef unsigned int u32;

extern void d3des_cook_key(u8 key[8], int mode, u32 res[32]);
/* Sets the key register [res] according to the hexadecimal
 * key contained in the 8 bytes of [key], according to the DES,
 * for encryption or decryption according to [mode].
 */

extern void d3des_transform(u32 key[32], u8 from[8], u8 to[8]);
/* Encrypts/Decrypts (according to the key [key])
 * one block of eight bytes at address 'from'
 * into the block at address 'to'.  They can be the same.
 */
