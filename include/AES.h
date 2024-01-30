#pragma once
#include <stdint.h>
#include <stdlib.h>

void AESEnc(uint8_t* Data, const uint8_t* Key);

void AESDec(uint8_t* Data, const uint8_t* Key);