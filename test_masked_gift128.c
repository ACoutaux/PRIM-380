#include "masked_gift128.c"

uint8_t P[16] = {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43, 0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1};
const uint8_t K[16] = {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7, 0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37};
uint8_t C[16]; //variable to contain output ciphertext 

int main(void) {    

    masked_giftb128(P,K,C);
    return 0;
}