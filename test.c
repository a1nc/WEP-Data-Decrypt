#include <sys/types.h>
#include <stdio.h>
#include "rc4.c"
#include "myhex.c"

int main(int argc, char* argv[]){

    int dataLength = 140;
    int keyLength = 8;
    char CipherText[]={"22bb369dbe4ae322ebea74ee9fae654df511eafaa7e5e5b8b4228d6122c05c0be7b1320c0b96d758b3319f2c57b394887226d90d00d1439ffd00307835a9c8615f224bb332ccaa66a1108e7cf2033a64a55a859abff268ff5e6e407deef036a4b83e65ac0615c892280ec3f833609d3addb3e0373ba65a12e85812b66c89a185f00afe518b74988a2007d090"}; 
    //char CipherText[]={"5d30c516d137b004e7dbecf3783059203487dc042dc5817020b1a9e83776ef09daf99b7a7a8df4f4f14d8d5e263ed8a8084091fe70f4b1c44840ca9f1254a0ecaf6b76a5e564e183ec9a65255f7fe4cb4844d23df933fe3d8e707208a2a087e1969d8c1fdca1a1d7ac0f48e0695f8b60a91c3a25fe2f54c4ed55a49eccdf2a4106d818d4be65b5716135b419"};
    unsigned char dataStream[140];
    
    HexDataToChar(dataStream,CipherText);

    printf("\nCipherText:\n");
    for (int i = 0; i < dataLength ; i++) {
        printf("%02x ",dataStream[i]);
        if((i+1)%16==0)
        {
            putchar('\n');
        }
    }
    printf("\n");
    
    unsigned char encryp[dataLength];
    unsigned char key[8] = {0xb0, 0x2c, 0x09, 0x11,0x12,0x22,0x33,0x34};
    //unsigned char key[8]={0xb0,0x2c,0x09,0x03,0x14,0x30,0x33,0x09};
    struct rc4_state state;

    rc4_init(&state, key, keyLength);// this code is very important
    rc4_crypt(&state, dataStream, encryp, dataLength);
    printf("\nDecryptText:\n");
    for (int i = 0; i < dataLength ; i++) {
        printf("%02x ",encryp[i]);
        if((i+1)%16==0)
        {
            putchar('\n');
        }
    }
    printf("\n");
   /*
    printf("\nafter \n");
    rc4_init(&state, key, keyLength);// this code is very important
    rc4_crypt(&state, encryp, decryp, dataLength);
    for (int i = 0; i < dataLength ; i++) {
        printf("%02x,",decryp[i]);
    }
    printf("\n");
    */
    return 0;
}


