#include "affine_masking.c"

int main(void) {

    struct mask affine_mask_x;
    uint8_t demasked_x,mul_masking,x;

    for (int i=0; i<1000; i++) {

        x=0; //for while condition 

        while (x==0) {
        getrandom(&x, sizeof(uint8_t), GRND_NONBLOCK) == -1 ?
            perror("getrandom") : "";
        }

        // ----------------- MASKING -----------------------------
        affine_mask_x = affine_masking(x);

        // -----------------  DEMASKING ------------------------------

        mul_masking = affine_mask_x.masked_x ^ affine_mask_x.r0;
        //printf("mul_masking : %d\n",mul_masking);

        demasked_x = search_Alog_Table(mul_masking);
        if (demasked_x < LogTable[affine_mask_x.r1]) {
            demasked_x = demasked_x + 255; //modulo de la fonction mul dans GF(256)
        }

        if ((demasked_x - LogTable[affine_mask_x.r1]) == 0) {
            demasked_x = 1; //this case means that x=1 (because x can't be 0 in function mul GF(256))
        } else {
            demasked_x = search_Log_Table(demasked_x - LogTable[affine_mask_x.r1]);
        }

        if (demasked_x != x) {
            printf("error with x = %d with r0 = %d and r1 = %d value_found : %d\n", x,affine_mask_x.r0,affine_mask_x.r1,demasked_x);
        }
    }
    printf("All passed\n");

    return 0;
}