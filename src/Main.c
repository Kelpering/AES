#include <stdio.h>
#include "../include/AES.h"

int main()
{
    printf("\n");
    uint8_t Data[] = {1, 2, 3};

    AES(Data, Data);
    printf("Data: %d\n", Data[0]);

    return 0;
}