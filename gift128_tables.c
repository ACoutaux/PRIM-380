/*
GIFT-128-128 implementation
Date: 09 March 2017
Done by: Siang Meng Sim
Edited on: 12 March 2017
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> 
#include <time.h>
#include <string.h>
#include "affine_masking.c"                         


//Sbox table
const unsigned char GIFT_S[16] = { 1,10, 4,12, 6,15, 3, 9, 2,13,11, 7, 5, 0, 8,14};

//Bit permutation table
const unsigned char GIFT_P[]={
/* Block size = 128 */
  0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
  4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
  8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
 12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
 16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
 20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
 24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
 28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
};

//Round constants
const unsigned char GIFT_RC[62] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20
};

//Encryption function declaration
void enc128(unsigned char* , unsigned char* , int , int ); 

//Main program --> Masking datas and calling enc128
int main() {

unsigned char P[32], K[32];
for (int i=0; i<32; i++) P[i] = 0x1;
for (int i=0; i<32; i++) K[i] = 0x0;

//A supprimer plus tard : pour tester le plaintext
P[2] = 0xf;
P[7] = 0x3;

printf("Plaintext_4bits = ");
for (int i=0; i<32; i++){
    printf("%0x",P[31-i]);
    if (i%2) {printf(" ");}
}
printf("\n");

//------------------------------MASKING PLAINTEXT------------------------------------

uint8_t P_octets[16]; //mise en octets du plaintext pour appliquer la fonction de masquage
struct mask masked_bits;

for (int i=0; i<31; i++) {
    if (!(i%2)) {
        P_octets[i/2] = (uint8_t)(P[i+1]<<4 | P[i]);
    }
}

//Disp P_octets
printf("Plaintext_octets : ");
for (int i=15; i>=0; i--) {
    printf("%02x ", P_octets[i]);
}
printf("\n");

masked_bits = affine_masking(P_octets);

//Affichage des octets masqués
printf("Plaintext_octets_masqued : ");
for(int i=15; i>=0; i--) {
    printf("%02x ", masked_bits.masked_x[i]);
}
printf("\n");

//Mise des octets du masked_bits dans le plaintext P (conversion des octets en paquets de 4 bits)
for(int i=0; i<15; i++) {
    P[2*i] = masked_bits.masked_x[i] & 0b00001111;
    P[(2*i) + 1] = (masked_bits.masked_x[i] & 0b11110000)>>4;
}
//Bits 30 31
P[30] = masked_bits.masked_x[15] & 0b00001111;
P[31] = (masked_bits.masked_x[15] & 0b11110000)>>4;

//Disp P
printf("Plaintext_4bits_masqued : ");
for (int i=0; i<32; i++){
    printf("%0x",P[31-i]);
    if (i%2) {printf(" ");}
}
printf("\n");

//-------------------------------DEMASKING PLAINTEXT---------------------------------------

// Mise des 4-bits en octets
for (int i=0; i<31; i++) {
    if (!(i%2)) {
        P_octets[i/2] = (uint8_t)(P[i+1]<<4 | P[i]);
    }
}

// Fonction de demasquage appliquee aux octets
masked_bits = affine_demasking(masked_bits);

// Affichage du plaintext demasque en octets  
printf("Plaintext_octets_demasqued : ");
for(int i=15; i>=0; i--) {
    printf("%02x ", masked_bits.demasked_x[i]);
}
printf("\n");

// Mise des octets en 4bits
for(int i=0; i<15; i++) {
    P[2*i] = masked_bits.demasked_x[i] & 0b00001111;
    P[(2*i) + 1] = (masked_bits.demasked_x[i] & 0b11110000)>>4;
}
//Bits 30 31
P[30] = masked_bits.demasked_x[15] & 0b00001111;
P[31] = (masked_bits.demasked_x[15] & 0b11110000)>>4;

//Affichage du plaintext demasque en 4bits
printf("Plaintext_4bits_demasqued : ");
for (int i=0; i<32; i++){
    printf("%0x",P[31-i]);
    if (i%2) {printf(" ");}
}
printf("\n");


//-----------------------------------------------------------------------------------

printf("masterkey = ");
    for (int i=0; i<32;i++){
        printf("%0x",K[31-i]);
        if (i%2) {printf(" ");}
    }
printf("\n");

enc128(P,K,40,1);

printf("Ciphertext = ");
for (int i=0; i<32; i++){
    printf("%0x",P[31-i]);
    if (i%2) {printf(" ");}
}
printf("\n");

return 0;}


void enc128(unsigned char* input, unsigned char* masterkey, int no_of_rounds, int print_details){ //bool print_details
printf("----------encryption----------");
printf("\n\n");
    unsigned char key[32];
    for (int i=0; i<32;i++){
        key[i] = masterkey[i];
    }
    //input = MSB [15][14]...[1][0] LSB
    //key = MSB [31][30]...[1][0] LSB
if (print_details){
    printf("input = ");
    for (int i=0; i<32; i++){
        printf("%0x",input[31-i]);
        if (i%2) {printf(" ");}
    }
    printf("\n");
    printf("key = ");
    for (int i=0; i<32;i++){
        printf("%0x",key[31-i]);
        if (i%2) {printf(" ");}
    }
    printf("\n");
    
}


unsigned char bits[128], perm_bits[128];
unsigned char key_bits[128];
unsigned char temp_key[32];
for (int r=0; r<no_of_rounds; r++){

    //SubCells
    for (int i=0; i<32; i++){
        input[i] = GIFT_S[input[i]];
    }

    if (print_details){
        printf("%d: after SubCells: ",r); //setw(2)?
        for (int i=0; i<32; i++){
            printf("%0x",input[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n");
    }

    //PermBits
    //input to bits
    for (int i=0; i<32; i++){
        for (int j=0; j<4; j++){
            bits[4*i+j] = (input[i] >> j) & 0x1;
        }
    }
    //permute the bits
    for (int i=0; i<128; i++){
        perm_bits[GIFT_P[i]] = bits[i];
    }
    //perm_bits to input
    for (int i=0; i<32; i++){
        input[i]=0;
        for (int j=0; j<4; j++){
             input[i] ^= perm_bits[4*i+j] << j;
        }
    }

    if (print_details){
        printf("%d: after PermBits: ",r);
        for (int i=0; i<32; i++){
            printf("%0x",input[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n");
    }


    //AddRoundKey
    //input to bits
    for (int i=0; i<32; i++){
        for (int j=0; j<4; j++){
            bits[4*i+j] = (input[i] >> j) & 0x1;
        }
    }
    //key to key_bits
    for (int i=0; i<32; i++){
        for (int j=0; j<4; j++){
            key_bits[4*i+j] = (key[i] >> j) & 0x1;
        }
    }

    //add round key
    int kbc=0;  //key_bit_counter
    for (int i=0; i<32; i++){
        bits[4*i+1] ^= key_bits[kbc];
        bits[4*i+2] ^= key_bits[kbc+64];
        kbc++;
    }

    //add constant
    bits[3] ^= GIFT_RC[r] & 0x1;
    bits[7] ^= (GIFT_RC[r]>>1) & 0x1;
    bits[11] ^= (GIFT_RC[r]>>2) & 0x1;
    bits[15] ^= (GIFT_RC[r]>>3) & 0x1;
    bits[19] ^= (GIFT_RC[r]>>4) & 0x1;
    bits[23] ^= (GIFT_RC[r]>>5) & 0x1;
    bits[127] ^= 1;

    //bits to input
    for (int i=0; i<32; i++){
        input[i]=0;
        for (int j=0; j<4; j++){
             input[i] ^= bits[4*i+j] << j;
        }
    }

    if (print_details){
        printf("%d: after AddRoundKeys: ",r);
        for (int i=0; i<32; i++){
            printf("%0x",input[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n");
    }

    //key update
    //entire key>>32
    for(int i=0; i<32; i++){
        temp_key[i] = key[(i+8)%32];
    }
    for(int i=0; i<24; i++) key[i] = temp_key[i];
    //k0>>12
    key[24] = temp_key[27];
    key[25] = temp_key[24];
    key[26] = temp_key[25];
    key[27] = temp_key[26];
    //k1>>2
    key[28] = ((temp_key[28]&0xc)>>2) ^ ((temp_key[29]&0x3)<<2);
    key[29] = ((temp_key[29]&0xc)>>2) ^ ((temp_key[30]&0x3)<<2);
    key[30] = ((temp_key[30]&0xc)>>2) ^ ((temp_key[31]&0x3)<<2);
    key[31] = ((temp_key[31]&0xc)>>2) ^ ((temp_key[28]&0x3)<<2);

    if (print_details){
        printf("%d: updated Key: ",r);
        for (int i=0; i<32; i++){
            printf("%0x",key[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n\n");
    }
}

    if (print_details){
        printf("input = ");
        for (int i=0; i<32; i++){
            printf("%0x",input[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n");
        printf("key = ");
        for (int i=0; i<32;i++){
            printf("%0x",key[31-i]);
            if (i%2) {printf(" ");}
        }
        printf("\n");
    }
return;
}
