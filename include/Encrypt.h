#pragma once

#include <vector>
#include <string>
#include <cstdlib>
#include <time.h>
#include "AES.h"

/**
 * A helper class that implements modes, conversions, and other useful functions for dealing with AES-128 encryption.
*/
class Encrypt
{
    // // PADDING (PCKS#7) (pad with the number of padding bytes)
    // // ECB
    //! Base64 stolen, probably rewrite
    // // BYTE ARRAY -> BASE64
    // // BASE64 -> BYTE ARRAY
    // // Randomized key func
    // CBC

    private:
        void PadVector(std::vector<uint8_t>* vector);
        void InvPadVector(std::vector<uint8_t>* vector);
        const std::string Base64Enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
    public:
        Encrypt();
        void ECBEncrypt(std::vector<uint8_t>* plaintext, uint8_t* key);
        void ECBDecrypt(std::vector<uint8_t>* ciphertext, uint8_t* key);
        std::string VectorString(std::vector<uint8_t> const vector);
        std::vector<uint8_t> RandomKey();
        
        //! Base64 functions stolen, probably replace later.
        std::string Base64Encode(uint8_t const* buf, unsigned int bufLen);
        std::vector<uint8_t> Base64Decode(std::string const& encoded_string);

};
