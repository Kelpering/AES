#include "Encrypt.h"

//* uint8_t* Encrypt::PadArr(uint8_t* plaintext, uint64_t size)
//* {
//*     uint8_t PadByte = 16 - (size % 16);

//*     uint8_t* NewArray = new uint8_t[size+PadByte];
//*     //* Assign plaintext bytes to NewArray
//*     for(uint64_t i = 0; i < size; i++)
//*     {
//*         NewArray[i] = plaintext[i];
//*     }
//*     //* All new slots are filled with PadByte
//*     for(uint64_t i = size; i < size+PadByte; i++)
//*     {
//*         NewArray[i] = PadByte;
//*     }

//*     return NewArray;
//* }

void Encrypt::PadVector(std::vector<uint8_t>* vector)
{
    std::size_t size = vector->size();

    uint8_t PadByte = 16 - (vector->size() % 16);

    for (std::size_t i = size; i < (size + PadByte); i++)
    {
        vector->push_back(PadByte);
    }
    vector->shrink_to_fit();

    return;
}

void Encrypt::InvPadVector(std::vector<uint8_t>* vector)
{
    uint8_t PadByte = *(vector->end() - 1);
    vector->resize(vector->size() - PadByte);

    vector->shrink_to_fit();

    return;
}

void Encrypt::ECBEncryptNew(std::vector<uint8_t>* plaintext, uint8_t* key)
{
    //* Pads vector to be a multiple of 16.
    //* Last byte is the number of bytes to cut in Decrypt.
    PadVector(plaintext);

    AES Aes;
    for (int i = 0; i < plaintext->size(); i+=16)
    {
        //* The address of the (i)th element in plaintext.
        Aes.Encrypt(&(*plaintext)[i], key);
    }
}

void Encrypt::ECBDecryptNew(std::vector<uint8_t>* ciphertext, uint8_t* key)
{
    AES Aes;
    for (int i = 0; i < ciphertext->size(); i+=16)
    {
        //* The address of the (i)th element in ciphertext.
        Aes.Decrypt(&(*ciphertext)[i], key);
    }

    //* Unencrypted text is still non-functional with PadByte at the end
    //* This cuts PadByte, returning the ciphertext to its previous status.
    InvPadVector(ciphertext);
}