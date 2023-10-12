
#include "md5.h"
// These vars will contain the hash
//xuint32_t h0, h1, h2, h3;

void md5(uint8_t *initial_msg, size_t initial_len, uint32_t *h0, uint32_t *h1, uint32_t *h2, uint32_t *h3) {

    // Message (to prepare)
    uint8_t *msg = NULL;
    int new_len;
    uint32_t bits_len;
    int offset;
    uint32_t *w;
    uint32_t a, b, c, d, i, f, g, temp;

    // Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating

    // r specifies the per-round shift amounts
    const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                          5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    // Initialize variables - simple count in nibbles:
    *h0 = 0x67452301;
    *h1 = 0xefcdab89;
    *h2 = 0x98badcfe;
    *h3 = 0x10325476;

    // Pre-processing: adding a single 1 bit
    //append "1" bit to message    
    /* Notice: the input bytes are considered as bits strings,
       where the first bit is the most significant bit of the byte.[37] */

    // Pre-processing: padding with zeros
    //append "0" bit until message length in bit ≡ 448 (mod 512)
    //append length mod (2 pow 64) to message

    for(new_len = initial_len*8 + 1; new_len%512!=448; new_len++);
    new_len /= 8;

    msg = (uint8_t*)calloc(new_len + 64, 1); // also appends "0" bits 
                                   // (we alloc also 64 extra bytes...)
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 128; // write the "1" bit

    bits_len = 8*initial_len; // note, we append the len
    memcpy(msg + new_len, &bits_len, 4);           // in bits at the end of the buffer

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        w = (uint32_t *) (msg + offset);

#ifdef DEBUG
        printf("offset: %d %x\n", offset, offset);

        int j;
        for(j =0; j < 64; j++) printf("%x ", ((uint8_t *) w)[j]);
        puts("");
#endif

        // Initialize hash value for this chunk:
        a = *h0;
        b = *h1;
        c = *h2;
        d = *h3;

        // Main loop:
        for(i = 0; i<64; i++) {

             if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

             temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        *h0 += a;
        *h1 += b;
        *h2 += c;
        *h3 += d;

    }

    // cleanup
    free(msg);

}

unsigned  int get_lower_16_bits(char *msg, unsigned int len)
{
    uint32_t h0, h1, h2, h3;   
    md5((uint8_t*)msg, len,&h0, &h1, &h2, &h3);
    return h0 & 0x0f;
}
unsigned int get_lower_256_bits(char *msg, unsigned int len)
{
    uint32_t h0, h1, h2, h3;   
    md5((uint8_t*)msg, len,&h0, &h1, &h2, &h3);
    return h0 & 0xff;
}

unsigned int get_lower_4096_bits(char *msg, unsigned int len)
{
    uint32_t h0, h1, h2, h3;   
    md5((uint8_t*)msg, len,&h0, &h1, &h2, &h3);
    return h0 & 0xfff;
}
/*
int main(int argc, char **argv) {

    uint32_t h0, h1, h2, h3;
    if (argc < 2) {
        printf("usage: %s 'string'\n", argv[0]);
        return 1;
    }

    char *msg = argv[1];
    size_t len = strlen(msg);

    // benchmark

        md5((uint8_t*)msg, len,&h0, &h1, &h2, &h3);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    uint8_t *p;

    // display result

    printf("%d\n", get_lower_16_bits(msg, strlen(msg)));
    p=(uint8_t *)&h0;
    printf("\n%d\n", p[0]);
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h0);

    p=(uint8_t *)&h1;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h1);

    p=(uint8_t *)&h2;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h2);

    p=(uint8_t *)&h3;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h3);
    puts("");

    return 0;
}

*/
