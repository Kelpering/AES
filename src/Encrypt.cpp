#include "Encrypt.h"

/**
 * Pads a Vector to a multiple of 16 bytes, uses the PKCS#7 method.
 * 
 * @param *vector Pointer to the vector to pad.
*/
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

/**
 * Unpads a Vector using the last byte to know how long the vector previously was. Uses PKCS#7.
 * 
 * @param *vector Pointer to the vector to unpad.
*/
void Encrypt::InvPadVector(std::vector<uint8_t>* vector)
{
    uint8_t PadByte = *(vector->end() - 1);
    vector->resize(vector->size() - PadByte);

    vector->shrink_to_fit();

    return;
}

/**
 * Encrypts a block any size using the AES-128 protocol using a key.
 * 
 *! @warning Overwrites plaintext.
 * 
 * @param *plaintext Pointer to a vector containing the plaintext to encrypt.
 * @param *key Pointer to a 16 byte array containing the key to encrypt with.
*/
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

/**
 * Decrypts a block of any size with a key of 16 bytes using the AES protocol. 
 * 
 *! @warning Overwrites ciphertext.
 * 
 * @param *ciphertext Pointer to a vector containing the ciphertext to decrypt.
 * @param *key Pointer to a 16 byte array containing the key to decrypt with.
*/
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