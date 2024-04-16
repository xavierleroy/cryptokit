/* Poly1305 implementation written by Andrew Moon,
          https://github.com/floodyberry/poly1305-donna
   License: MIT or public domain.
   Minor adaptations for Cryptokit by Xavier Leroy. */

#ifndef POLY1305_DONNA_H
#define POLY1305_DONNA_H

#include <stddef.h>

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

EXPORT void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
EXPORT void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
EXPORT void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

#endif /* POLY1305_DONNA_H */

