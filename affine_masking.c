#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/random.h>

typedef unsigned char BYTE;


const uint8_t LogTable[256] = {
    0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
    100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
    125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
    101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
    150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
    102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
    126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
    43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
    175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
    44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
    127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
    204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
    151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
    83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
    68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
    103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7, 
};

const uint8_t ALogTable[256] = {
    1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
    95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
    229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
    83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
    131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
    181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
    254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
    251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
    195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
    159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
    155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
    252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
    69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
    18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
    57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1,
};


struct mask {
    uint8_t r1; //multiplicative mask
    uint8_t r0; //additive mask
    uint8_t masked_x[16]; //masked 128 bits array
    uint8_t demasked_x[16]; //demasked 128 bits array
};

uint8_t search_Alog_Table(uint8_t mul_masking) {
    for (int i=0; i<256; i++) {
        if (ALogTable[i] == mul_masking) {
            return i;
        }
    }
    return 0;
}

uint8_t search_Log_Table(uint8_t mul_masking) {
    for (int i=0; i<256; i++) {
        if (LogTable[i] == mul_masking) {
            return i;
        }
    }
    return 0;
}

uint8_t affine_mul(uint8_t x1, uint8_t x2) {
    if (x1!= 0 && x2!=0) {
        return ALogTable[(LogTable[x1] + LogTable[x2])%255];
    } else {
        perror("illegal 0 value in affine_mul");
        return 0;
    }
} 

struct mask affine_masking(uint8_t x[16]) {

    struct mask m;
    uint8_t mul_masking;

    m.r1 = 0; //pour initialiser le while

    //Si la fonction random renvoie une erreur la def de la macro GRND_NONBLOCK permet de renvoyer -1
    getrandom(&m.r0, sizeof(uint8_t), GRND_NONBLOCK) == -1 ?
        perror("getrandom") : "";
        //printf("r0 : %d\n",m.r0);

    //Le masque multiplicatif r1 ne doit pas valoir 0
    while(m.r1 == 0) {
        getrandom(&m.r1, sizeof(uint8_t), GRND_NONBLOCK) == -1 ?
            perror("getrandom") : "";
            //printf("r1 : %d\n",m.r1);
    }

    //Put r0 and r1 into two concatenante 4-bits masks
    m.r0 = (m.r0 & 0b11110000) | (m.r0 >> 4);
    m.r1 = (m.r1 & 0b11110000) | (m.r1 >> 4);
    //printf("r1 is : %02x\n", m.r1);

    for (int i=0; i<16; i++) {
        mul_masking = affine_mul(x[i],m.r1);
        m.masked_x[i] = mul_masking ^ m.r0;
    }

    return m;
}

struct mask affine_demasking(struct mask m) {
    uint8_t mul_masking, demasked_x;

    for(int i=0; i<16; i++) {
        mul_masking = m.masked_x[i] ^ m.r0;

        demasked_x = search_Alog_Table(mul_masking);
        if (demasked_x < LogTable[m.r1]) {
            demasked_x = demasked_x + 255; //modulo de la fonction mul dans GF(256)
        }

        if ((demasked_x - LogTable[m.r1]) == 0) {
            demasked_x = 1; //this case means that x=1 (because x can't be 0 in function mul GF(256))
        } else {
                demasked_x = search_Log_Table(demasked_x - LogTable[m.r1]);
        }
        m.demasked_x[i] = demasked_x;
    }

    return m;
}