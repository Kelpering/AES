#include "Encrypt.h"
#include <iostream>

Encrypt::Encrypt()
{
    srand(time(0));
}

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
void Encrypt::ECBEncrypt(std::vector<uint8_t>* plaintext, uint8_t* key)
{
    //* Pads vector to be a multiple of 16.
    //* Last byte is the number of bytes to cut in Decrypt.
    PadVector(plaintext);

    AES Aes;
    for (size_t i = 0; i < plaintext->size(); i+=16)
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
void Encrypt::ECBDecrypt(std::vector<uint8_t>* ciphertext, uint8_t* key)
{
    AES Aes;
    for (size_t i = 0; i < ciphertext->size(); i+=16)
    {
        //* The address of the (i)th element in ciphertext.
        Aes.Decrypt(&(*ciphertext)[i], key);
    }

    //* Unencrypted text is still non-functional with PadByte at the end
    //* This cuts PadByte, returning the ciphertext to its previous status.
    InvPadVector(ciphertext);
}

static inline bool is_base64(uint8_t c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Encrypt::Base64Encode(uint8_t const* buf, unsigned int bufLen) 
{
  std::string ret;
  int i = 0;
  int j = 0;
  uint8_t char_array_3[3];
  uint8_t char_array_4[4];

  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += Base64Enc[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += Base64Enc[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::vector<uint8_t> Encrypt::Base64Decode(std::string const& encoded_string) 
{
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  uint8_t char_array_4[4], char_array_3[3];
  std::vector<uint8_t> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = Base64Enc.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
          ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = Base64Enc.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}

std::string Encrypt::VectorString(std::vector<uint8_t> const vector)
{
    std::string VecString;
    for(size_t i = 0; i < vector.size(); i++)
    {
        VecString += vector[i];
    }
    return VecString;
}

std::vector<uint8_t> Encrypt::RandomKey()
{
    std::vector<uint8_t> key;
    for (int i = 0; i < 16; i++)
    {
        key.push_back(rand() % 256);
    }
    return key;
}