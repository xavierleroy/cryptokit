/* SHA-3 (Keccak) cryptographic hash function */
/* Code adapted from the "readable" implementation written by
   Markku-Juhani O. Saarinen <mjos@iki.fi> */

#include <assert.h>
#include <string.h>
#include <caml/config.h>
#include "keccak.h"

#define KECCAK_ROUNDS 24

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const u64 keccakf_rndc[24] = 
{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

#if 0
/* Inlined */
static const int keccakf_rotc[24] = 
{
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = 
{
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 
};
#endif

/* Update the state with KECCAK_ROUND rounds */

static void KeccakPermutation(u64 st[25])
{
  int round, j;
    u64 t, bc[5];

    for (round = 0; round < KECCAK_ROUNDS; round++) {

        // Theta
#define THETA1(i) \
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20]

      THETA1(0); THETA1(1); THETA1(2); THETA1(3); THETA1(4);

#define THETA2(i) \
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1); \
            st[0 + i] ^= t; \
            st[5 + i] ^= t; \
            st[10 + i] ^= t; \
            st[15 + i] ^= t; \
            st[20 + i] ^= t

      THETA2(0); THETA2(1); THETA2(2); THETA2(3); THETA2(4);


        // Rho Pi

#define RHOPI(i, rotc, piln) \
            bc[0] = st[piln]; \
            st[piln] = ROTL64(t, rotc); \
            t = bc[0]

        t = st[1];
        RHOPI(0, 1, 10); RHOPI(1, 3, 7); RHOPI(2, 6, 11); RHOPI(3, 10, 17);
        RHOPI(4, 15, 18); RHOPI(5, 21, 3); RHOPI(6, 28, 5); RHOPI(7, 36, 16);
        RHOPI(8, 45, 8); RHOPI(9, 55, 21); RHOPI(10, 2, 24); RHOPI(11, 14, 4);
        RHOPI(12, 27, 15); RHOPI(13, 41, 23); RHOPI(14, 56, 19); RHOPI(15, 8, 13);
        RHOPI(16, 25, 12); RHOPI(17, 43, 2); RHOPI(18, 62, 20); RHOPI(19, 18, 14);
        RHOPI(20, 39, 22); RHOPI(21, 61, 9); RHOPI(22, 20, 6); RHOPI(23, 44, 1);

        //  Chi

#define CHI1(i,j) \
                bc[i] = st[j + i]
#define CHI2(i,j) \
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5]

        for (j = 0; j < 25; j += 5) {
          CHI1(0,j); CHI1(1,j); CHI1(2,j); CHI1(3,j); CHI1(4,j);
          CHI2(0,j); CHI2(1,j); CHI2(2,j); CHI2(3,j); CHI2(4,j);
        }

        //  Iota
        st[0] ^= keccakf_rndc[round];
    }
}

/* Absorb the given data and permute */

static void KeccakAbsorb(u64 st[25], unsigned char * p, int rsiz)
{
  int i;
  rsiz = rsiz / 8;
  for (i = 0; i < rsiz; i += 1, p += 8) {
    // fixme: use direct access for little-endian platforms without
    // alignment constraints?
      unsigned int l = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
      unsigned int h = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
      st[i] ^= l | ((unsigned long long) h << 32);
  }
  KeccakPermutation(st);
}

/* Exported interface */

void SHA3_init(struct SHA3Context * ctx, int hsiz)
{
  assert (hsiz == 224 || hsiz == 256 || hsiz == 384 || hsiz == 512);
  ctx->hsiz = hsiz / 8;
  ctx->rsiz = 200 - 2 * ctx->hsiz;
  ctx->numbytes = 0;
  memset(ctx->state, 0, sizeof(ctx->state));
}

void SHA3_absorb(struct SHA3Context * ctx, 
                 unsigned char * data,
                 unsigned long len)
{
  int n;

  /* If data was left in buffer, fill with fresh data and absorb */
  if (ctx->numbytes != 0) {
    n = ctx->rsiz - ctx->numbytes;
    if (len < n) {
      memcpy(ctx->buffer + ctx->numbytes, data, len);
      ctx->numbytes += len;
      return;
    }
    memcpy(ctx->buffer + ctx->numbytes, data, n);
    KeccakAbsorb(ctx->state, ctx->buffer, ctx->rsiz);
    data += n;
    len  -= n;
  }
  /* Absorb data in blocks of [rsiz] bytes */
  while (len >= ctx->rsiz) {
    KeccakAbsorb(ctx->state, data, ctx->rsiz);
    data += ctx->rsiz;
    len  -= ctx->rsiz;
  }
  /* Save remaining data */
  if (len > 0) memcpy(ctx->buffer, data, len);
  ctx->numbytes = len;
}

void SHA3_extract(unsigned char padding,
                  struct SHA3Context * ctx,
                  unsigned char * output)
{
  int i, j, n;

  /* Apply final padding */
  n = ctx->numbytes;
  ctx->buffer[n] = padding;
  n++;
  memset(ctx->buffer + n, 0, ctx->rsiz - n);
  ctx->buffer[ctx->rsiz - 1] |= 0x80;

  /* Absorb remaining data + padding */
  KeccakAbsorb(ctx->state, ctx->buffer, ctx->rsiz);

  /* Extract hash as low bits of state */
  for (i = 0, j = 0; j < ctx->hsiz; i += 1, j += 8) {
    u64 st = ctx->state[i];
    output[j] = st;
    output[j + 1] = st >> 8;
    output[j + 2] = st >> 16;
    output[j + 3] = st >> 24;
    if (j + 4 >= ctx->hsiz) break;
    output[j + 4] = st >> 32;
    output[j + 5] = st >> 40;
    output[j + 6] = st >> 48;
    output[j + 7] = st >> 56;
  }
}
