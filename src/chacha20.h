/* Based on D. J. Bernstein's chacha-regs.c version 200801118,
  https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/regs/chacha.c
  The initial code is in the public domain */

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t input[16];           /* The current state */
  uint8_t output[64];           /* Output data for the current state */
  int next;                     /* Index of next unused byte in output */
  int iv_length;                /* 8 or 12 */
} chacha20_ctx;

EXPORT void chacha20_init(chacha20_ctx * ctx,
                          const uint8_t * key, size_t key_length,
                          const uint8_t * iv, size_t iv_length,
                          uint64_t ctr);

EXPORT void chacha20_extract(chacha20_ctx * ctx,
                             uint8_t * out, size_t len);

EXPORT void chacha20_transform(chacha20_ctx * ctx,
                               const uint8_t * in, uint8_t * out, size_t len);
