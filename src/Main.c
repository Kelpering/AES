#include <stdio.h>
#include "../include/AES.h"

int main()
{
    printf("\n");
    uint8_t Data[16] = {1, 2, 3};

    AESEnc(Data, Data);
    printf("Data: %d\n", Data[7]);

    return 0;
}