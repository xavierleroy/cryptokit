/* SHA-3 (Keccak) cryptographic hash function */

typedef unsigned long long u64;

struct SHA3Context {
  u64 state[25];
  unsigned char buffer[144];
  int numbytes;       /* number of bytes in buffer */
  int rsiz;           /* number of message bytes processed by permutation */
  int hsiz;           /* size of hash in bytes */
};

extern void SHA3_init(struct SHA3Context * ctx, int hsiz);

extern void SHA3_absorb(struct SHA3Context * ctx, 
                        unsigned char * data,
                        unsigned long len);

extern void SHA3_extract(unsigned char padding,
                         struct SHA3Context * ctx,
                         unsigned char * output);
