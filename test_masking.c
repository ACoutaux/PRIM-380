#include "affine_masking.c"

int main(void) {

    struct mask affine_mask_x;
    uint8_t demasked_x,x;

    for (int i=0; i<1000; i++) {

        x=0; //for while condition 

        while (x==0) {
        getrandom(&x, sizeof(uint8_t), GRND_NONBLOCK) == -1 ?
            perror("getrandom") : "";
        }

        // ----------------- MASKING -----------------------------
        affine_mask_x = affine_masking(x);

        // -----------------  DEMASKING ------------------------------

        demasked_x = affine_demasking(affine_mask_x);

        if (demasked_x != x) {
            printf("error with x = %d with r0 = %d and r1 = %d value_found : %d\n", x,affine_mask_x.r0,affine_mask_x.r1,demasked_x);
        }
    }
    printf("All passed\n"); 

    return 0;
}