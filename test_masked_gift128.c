#include "masked_gift128.c"

uint8_t P[16] = {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43, 0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1};
const uint8_t K[16] = {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7, 0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37};
uint8_t C[16]; //variable to contain output ciphertext 

int main(void) {    

    masked_giftb128(P,K,C);

    //Test & and . ditributivity
    //--------------------------
    /*uint8_t x, aff_mul_res_1,aff_mul_res_2, p1, p2, s1 = 0b11001010, s2 = 0b01011111;
    getrandom(&x, sizeof(uint8_t), GRND_NONBLOCK);
    aff_mul_res_1 = affine_mul(x,s1);
    aff_mul_res_2 = affine_mul(x,s2);
    p1 = aff_mul_res_1 | aff_mul_res_2;
    p2 = affine_mul(x,s1|s2);
    printf("P1 is : %02x,  P2 is : %02x\n", p1, p2);*/
    //------------------------------------------------

    return 0;
}