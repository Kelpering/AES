#pragma once

#include <vector>
#include "AES.h"

class Encrypt
{
    // PADDING (PCKS#7) (pad with the number of padding bytes)
    // ECB
    // BYTE ARRAY -> BASE64
    // BASE64 -> BYTE ARRAY
    // CBC

    private:
        // uint8_t* PadArr(uint8_t* plaintext, uint64_t size);
        // uint8_t* InvPadArr(uint8_t* ciphertext, uint64_t size);
        void PadVector(std::vector<uint8_t>* vector);
        void InvPadVector(std::vector<uint8_t>* vector);


    public:
        // uint8_t* ECBEncrypt(uint8_t* plaintext, uint64_t size, uint8_t* key);
        // uint8_t* ECBDecrypt(uint8_t* ciphertext, uint64_t size, uint8_t* key);
        void ECBEncryptNew(std::vector<uint8_t>* plaintext, uint8_t* key);
        void ECBDecryptNew(std::vector<uint8_t>* ciphertext, uint8_t* key);

};
