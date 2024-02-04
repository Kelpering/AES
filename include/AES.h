#pragma once
#include <stdint.h>
#include <stdlib.h>

/// @brief Encrypts Plaintext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Plaintext 16 bytes of Plaintext to encrypt, directly altered into Ciphertext.
/// @param Key 32 bytes of a key, used to encrypt Plaintext.
/// @warning InitSBox() must be run before the first encryption.
void AESEnc(uint8_t* Plaintext, const uint8_t* Key);

/// @brief Decrypts Ciphertext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Ciphertext 16 bytes of Ciphertext to decrypt, directly altered into Plaintext.
/// @param Key 32 bytes of a key, used to decrypt Ciphertext.
/// @warning InitInvSBox() must be run before the first decryption.
void AESDec(uint8_t* Ciphertext, const uint8_t* Key);


//? Init functions

/// @brief Initializes the internal "SBox" of AESEnc to allow for proper encryption, only called once.
void InitSBox();

/// @brief Initializes the internal "InvSBox" of AESDec to allow for proper decryption, only called once.
void InitInvSBox();
