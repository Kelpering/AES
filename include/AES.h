#pragma once
#include <stdint.h>
#include <stdlib.h>

void AESEnc(uint8_t* Plaintext, const uint8_t* Key);

void AESDec(uint8_t* Ciphertext, const uint8_t* Key);



static inline uint8_t XTimes(uint8_t X);

static inline uint8_t GMul(uint8_t X, uint8_t Y);