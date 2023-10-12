#ifndef SHA1_
#define SHA1_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>

typedef unsigned char boolean;
typedef unsigned char byte;
typedef byte *byteptr;
typedef char *string;
typedef unsigned int word32;
typedef unsigned long long word64;

#define SHA1_NR 80 
#define SHA1_BLOCK_LEN 64 // 64 * BYTE = 512 BIT
#define SHA1_OUT 160 >> 3
#define LENGTH_PAD_POS 56

typedef struct sha1_context
{
	word32 h[5];
} sha1_ctx; 

void sha1(sha1_ctx *ctx, byte *data, int byte_len, unsigned char **out);
#endif 
