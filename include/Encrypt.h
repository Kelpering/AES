#pragma once

#include <vector>
#include "AES.h"

/**
 * A class that implements the AES-128 16 byte functions with modes to allow for larger encryptions.
*/
class Encrypt
{
    // // PADDING (PCKS#7) (pad with the number of padding bytes)
    // // ECB
    // BYTE ARRAY -> BASE64
    // BASE64 -> BYTE ARRAY
    // CBC

    private:
        void PadVector(std::vector<uint8_t>* vector);
        void InvPadVector(std::vector<uint8_t>* vector);
    public:
        void ECBEncryptNew(std::vector<uint8_t>* plaintext, uint8_t* key);
        void ECBDecryptNew(std::vector<uint8_t>* ciphertext, uint8_t* key);
};
