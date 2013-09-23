/* MD5 context. */
typedef struct {
  unsigned state[4];                                   /* state (ABCD) */
  unsigned count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *ctx);
void MD5Update(MD5_CTX *context, const unsigned char *input, unsigned int inputLen);
void MD5Final(unsigned char digest[16], MD5_CTX *context);

