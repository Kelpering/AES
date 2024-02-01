#pragma once
#include <stdint.h>
#include <stdlib.h>

void AESEnc(uint8_t* Plaintext, const uint8_t* Key);

void AESDec(uint8_t* Ciphertext, const uint8_t* Key);

static uint8_t GInv(uint8_t a);