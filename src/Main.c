#include <stdio.h>
#include <time.h>
#include "../include/AES.h"

void PrintArr(uint8_t* Data);
void PrintBlock(uint8_t* Data);

int main()
{
    //* Initialization
    uint8_t Data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t Key[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    //* Print Data
    printf("Data Plaintext: ");
    PrintArr(Data);

    //* Encrypt and Print Data
    AESEnc(Data, Key);
    printf("Data Encrypted: ");
    PrintArr(Data);

    //* Decrypt and Print Data
    AESDec(Data, Key);
    printf("Data Decrypted: ");
    PrintArr(Data);


    printf("\nNow using a randomly generated key...\n");
    uint8_t* Key2 = AESKeyGen256(time(NULL));

    //* Print Data
    printf("Data Plaintext: ");
    PrintArr(Data);

    //* Encrypt and Print Data
    AESEnc(Data, Key2);
    printf("Data Encrypted: ");
    PrintArr(Data);

    //* Decrypt and Print Data
    AESDec(Data, Key2);
    printf("Data Decrypted: ");
    PrintArr(Data);

    free(Key2);

    return 0;
}

void PrintArr(uint8_t* Data)
{
    for (int i = 0; i < 16; i++)
    {
        printf("[0x%.2X] ", Data[i]);
    }
    printf("\n");
    return;
}

void PrintBlock(uint8_t* Data)
{
    for (int i = 0 ; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("[0x%.2X] ", Data[i*4+j]);
        }
        printf("\n");
    }
    printf("\n");
    return;
}
