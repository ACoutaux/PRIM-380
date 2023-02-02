/*
GIFT-128 (bitslice) implementations
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 23 Mar 2019
*/
#include <stdint.h>
#include <stdio.h>
#include "gift128.h"                                                                    ////
#include "affine_masking.c"                                                             ////

/*Round constants*/
const unsigned char GIFT_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A};

uint8_t cipher_tab[16];                                                                 ////

void extract_from_SBox(uint32_t S[4]) {                                                 ////
    int cpt = 0;                                                                        ////
    for (int i=15; i>-1; i--) {                                                         ////

        cipher_tab[i] = ((S[0] & (1u << cpt))>0) | ((S[1] & (1u << cpt))>0) << 1  | ((S[2] & (1u << cpt))>0) << 2 | ((S[3] & (1u << cpt))>0) << 3 | ((S[0] & (1u << (cpt+1)))>0) << 4 | ((S[1] & (1u << (cpt+1)))>0) << 5 | ((S[2] & (1u << (cpt+1)))>0) << 6 | ((S[3] & (1u << (cpt+1)))>0) << 7;                   
        cpt = cpt+2;                                                                    
    }                                                                                   ////
}                                                                                       ////

uint32_t rowperm(uint32_t S, int B0_pos, int B1_pos, int B2_pos, int B3_pos)
{
    uint32_t T = 0;
    int b;
    for (b = 0; b < 8; b++)  
    {
        T |= ((S >> (4 * b + 0)) & 0x1) << (b + 8 * B0_pos);
        T |= ((S >> (4 * b + 1)) & 0x1) << (b + 8 * B1_pos);
        T |= ((S >> (4 * b + 2)) & 0x1) << (b + 8 * B2_pos);
        T |= ((S >> (4 * b + 3)) & 0x1) << (b + 8 * B3_pos);
    }
    return T;
}

void masked_giftb128(uint8_t P[16], const uint8_t K[16], uint8_t C[16])
{
    int round, cpt_ = 0;                                                                ////
    struct mask Masked_P;                                                               ////  
    uint32_t S[4], T, masked_XOR;       
    uint16_t W[8], T6, T7;

    // -------------------------- PLAINTEXT ----------------------------------
    // -----------------------------------------------------------------------

    printf("PLAINTEXT : ");                                                             ////
    for (int i=0; i<16; i++) {                                                          ////
        printf("%02x ", P[i]);                                                          ////
    }                                                                                   ////
    printf("\n");                                                                       ////

    // ------------------------ MASKING PLAINTEXT ----------------------------
    // -----------------------------------------------------------------------

    Masked_P = affine_masking(P);
    printf("MASKED PLAINTEXT : ");
    for (int i=0; i<16 ; i++) {                                                         ////
        printf("%02x ", Masked_P.masked_x[i]);                                          ////
    }                                                                                   ////
    printf("\n");                                                                       ////

    // -------------------- MASKED PLAINTEXT IN SBOX ------------------------
    // ----------------------------------------------------------------------

    S[0] = 0x00000000;                                                                  ////
    S[1] = 0x00000000;                                                                  ////
    S[2] = 0x00000000;                                                                  ////
    S[3] = 0x00000000;                                                                  ////

    for (int i=15; i>-1; i--) {                                                         ////

        S[0] |= (((Masked_P.masked_x[i] & (1u << 0))>0) << cpt_) | ((Masked_P.masked_x[i] & (1u << 4))>0) << (cpt_+1);                             ////
        S[1] |= (((Masked_P.masked_x[i] & (1u << 1))>0) << cpt_) | ((Masked_P.masked_x[i] & (1u << 5))>0) << (cpt_+1);                             
        S[2] |= (((Masked_P.masked_x[i] & (1u << 2))>0) << cpt_) | ((Masked_P.masked_x[i] & (1u << 6))>0) << (cpt_+1);                             
        S[3] |= (((Masked_P.masked_x[i] & (1u << 3))>0) << cpt_) | ((Masked_P.masked_x[i] & (1u << 7))>0) << (cpt_+1);                             

        cpt_ += 2;                                                                      ////
    }

    // ---------------------- EXTRACT MASKED PLAINTEXT FROM SBOX ---------------
    // -------------------------------------------------------------------------

    extract_from_SBox(S);                                                               ////
    printf("EXTRACTED MASKED PLAINTEXT : ");                                            ////
    for (int i = 0; i < 16; i++)                                                        ////
    {                                                                                   ////
        printf("%02x ", cipher_tab[i]);                                                 ////
    }                                                                                   ////
    printf("\n");                                                                       ////

    // ------------------------- DEMASKING PLAINTEXT ---------------------------------
    // -------------------------------------------------------------------------------

    printf("DEMASKED PLAINTEXT : ");                                                    ////
    for (int i=0; i<16; i++) {                                                          ////
        Masked_P.masked_x[i] = cipher_tab[i];                                           ////
    }                                                                                   ////
    Masked_P = affine_demasking(Masked_P);                                              ////
    for (int i=0; i<16; i++) {                                                          ////
        printf("%02x ", Masked_P.demasked_x[i]);                                        ////
    }                                                                                   ////
    printf("\n");                                                                       ////


    W[0] = ((uint16_t)K[0] << 8) | (uint16_t)K[1];
    W[1] = ((uint16_t)K[2] << 8) | (uint16_t)K[3];
    W[2] = ((uint16_t)K[4] << 8) | (uint16_t)K[5];
    W[3] = ((uint16_t)K[6] << 8) | (uint16_t)K[7];
    W[4] = ((uint16_t)K[8] << 8) | (uint16_t)K[9];
    W[5] = ((uint16_t)K[10] << 8) | (uint16_t)K[11];
    W[6] = ((uint16_t)K[12] << 8) | (uint16_t)K[13];
    W[7] = ((uint16_t)K[14] << 8) | (uint16_t)K[15];

    for (round = 0; round < 1; round++) //rounds = 40
    {
        /*===SubCells===*/
        S[1] ^= S[0] & S[2];
        S[0] ^= S[1] & S[3];
        S[2] ^= S[0] | S[1];
        S[3] ^= S[2];
        S[1] ^= S[3];
        S[3] ^= 0xffffffff;
        S[2] ^= S[0] & S[1];

        T = S[0];
        S[0] = S[3];
        S[3] = T;

        /*
        extract_from_SBox(S);                                                           ////
        printf("subcells %d : ", round);                                                ////
        for (int i = 0; i < 16; i++)                                                    ////
        {                                                                               ////
            printf("%02x ", cipher_tab[i]);                                             ////
        }                                                                               ////
        printf("\n");                                                                   ////
        */

        /*===PermBits===*/
        S[0] = rowperm(S[0], 0, 3, 2, 1);
        S[1] = rowperm(S[1], 1, 0, 3, 2);
        S[2] = rowperm(S[2], 2, 1, 0, 3);
        S[3] = rowperm(S[3], 3, 2, 1, 0);

        /*
        extract_from_SBox(S);                                                           ////    
        printf("permbits %d : ", round);                                                ////
        for (int i = 0; i < 16; i++)                                                    ////
        {                                                                               ////
            printf("%02x ", cipher_tab[i]);                                             ////
        }                                                                               ////
        printf("\n");                                                                   ////
        */

        /*===AddRoundKey===*/
        masked_XOR = S[2] ^ (((uint32_t)W[2] << 16) | (uint32_t)W[3]);
        S[2] = masked_XOR;
        masked_XOR = S[1] ^ (((uint32_t)W[6] << 16) | (uint32_t)W[7]);
        S[1] = masked_XOR;

        extract_from_SBox(S);                                                           ////    
        printf("addroundkey %d : ", round);                                             ////
        for (int i = 0; i < 16; i++)                                                    ////
        {                                                                               ////
            printf("%02x ", cipher_tab[i]);                                             ////
        }                                                                               ////
        printf("\n");                                                                   ////

        /*Add round constant*/
        S[3] ^= 0x80000000 ^ GIFT_RC[round];

        /*===Key state update===*/
        T6 = (W[6] >> 2) | (W[6] << 14);
        T7 = (W[7] >> 12) | (W[7] << 4);
        W[7] = W[5];
        W[6] = W[4];
        W[5] = W[3];
        W[4] = W[2];
        W[3] = W[1];
        W[2] = W[0];
        W[1] = T7;
        W[0] = T6;

        /*
        extract_from_SBox(S);                                                           ////
        printf("addroundkeys %d : ", round);                                            ////
        for (int i = 0; i < 16; i++)                                                    ////
        {                                                                               ////
            printf("%02x ", cipher_tab[i]);                                             ////
        }                                                                               ////
        printf("\n");                                                                   ////

        printf("updated key %d : ", round);                                             ////
        for (int i = 0; i < 8; i++)                                                     ////
        {                                                                               ////
            printf("%04x ", W[i]);                                                      ////
        }                                                                               ////
        printf("\n\n");                                                                 ////

        if (round == 39) {                                                              ////                         
            printf("Ciphertext : ");                                                    ////
            for (int i = 0; i < 16; i++)                                                ////
            {                                                                           ////
                printf("%02x ", cipher_tab[i]);                                         ////
            }                                                                           ////
       }*/
    }

    C[0] = S[0] >> 24;
    C[1] = S[0] >> 16;
    C[2] = S[0] >> 8;
    C[3] = S[0];
    C[4] = S[1] >> 24;
    C[5] = S[1] >> 16;
    C[6] = S[1] >> 8;
    C[7] = S[1];
    C[8] = S[2] >> 24;
    C[9] = S[2] >> 16;
    C[10] = S[2] >> 8;
    C[11] = S[2];
    C[12] = S[3] >> 24;
    C[13] = S[3] >> 16;
    C[14] = S[3] >> 8;
    C[15] = S[3];

    return;
}