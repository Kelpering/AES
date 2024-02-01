#include <stdio.h>
#include "../include/AES.h"

void PrintArr(uint8_t* Data);
void PrintBlock(uint8_t* Data);

int main()
{
    uint8_t Data[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t Key[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    printf("\nData: ");
    PrintArr(Data);
    printf("Key:  ");
    PrintArr(Key);

    AESEnc(Data, Key);

    return 0;
}

void PrintArr(uint8_t* Data)
{
    for (int i = 0; i < 16; i++)
    {
        printf("[0x%X] ", Data[i]);
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
            printf("[0x%X] ", Data[i*4+j]);
        }
        printf("\n");
    }
    printf("\n");
    return;
}
