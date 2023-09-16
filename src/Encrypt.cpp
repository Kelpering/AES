// #include "Encrypt.h"

// //? To make this easier, I will use vectors to encrypt and decrypt as that will allow dynamic sizing without a new array
// //? Makes the whole process generally easier if you use the vector correctly
// //? I believe they will still work with the AES.h Function

// //! Whole Encrypt rewrite is required



// /**
//  * Takes a byte array plaintext and the size of the byte array. 
//  * Returns a new byte array with an AES compliant size with PCKS#7 padding.
//  * 
//  *! @warning Returns a dynamically allocated array, needs to be handled by user.
//  *! @warning The size of the dynamically allocated array is size+(16 - size % 16).
//  * 
//  * @param plaintext Array to be padded
//  * @param size Size of plaintext
//  * 
//  * @returns An allocated array to be used with AES modes.
// */
// uint8_t* Encrypt::PadArr(uint8_t* plaintext, uint64_t size)
// {
//     uint8_t PadByte = 16 - (size % 16);

//     uint8_t* NewArray = new uint8_t[size+PadByte];
//     //* Assign plaintext bytes to NewArray
//     for(uint64_t i = 0; i < size; i++)
//     {
//         NewArray[i] = plaintext[i];
//     }
//     //* All new slots are filled with PadByte
//     for(uint64_t i = size; i < size+PadByte; i++)
//     {
//         NewArray[i] = PadByte;
//     }

//     return NewArray;
// }

// /**
//  * Unpads the array to return ciphertext back to pure plaintext.
//  * 
//  *! @warning Returns a dynamically allocated array, needs to be handled by user.
//  *! @warning The size of the dynamically allocated array is size-(The final byte in the array). Ex: size = 16, arr[15] = 3, newsize = 13
//  *
//  * @param ciphertext Unencrypted byte array ciphertext to unpad.
//  * @param size Size of ciphertext byte array.
//  * 
//  * @returns An allocated array that contains the pure plaintext.
// */
// uint8_t* Encrypt::InvPadArr(uint8_t* ciphertext, uint64_t size)
// {
//     //* Last element in ciphertext
//     uint8_t PadByte = ciphertext[size-1];

//     uint8_t* NewArray = new uint8_t[size-PadByte];
//     //* Assign plaintext bytes to NewArray
//     for(uint64_t i = 0; i < size-PadByte; i++)
//     {
//         NewArray[i] = ciphertext[i];
//     }
//     //* All new slots are filled with PadByte

//     return NewArray;
// }

// /**
//  * Encrypts plaintext, padding is applied automatically. Mode: Electronic Code Book (ECB)
//  * 
//  * @param plaintext A byte array of plaintext to encrypt.
//  * @param key A byte array for the key, 16 bytes.
//  * 
//  * @returns A dynamically allocated array containing the ciphertext.
// */
// uint8_t* Encrypt::ECBEncrypt(uint8_t* plaintext, uint64_t size, uint8_t* key)
// {
//     AES Aes;
//     //* Creates array Padded with a NewSize that is divisible by 16
//     //! Padded is a dynamically allocated array
//     uint8_t* Padded = PadArr(plaintext, size);
//     uint32_t NewSize = size + (16-(size%16));

//     for(uint64_t i = 0; i < size; i+=16)
//     {
//         //* Should overwrite padded to contain encrypted values, 16 bytes at a time
//         Aes.Encrypt((Padded+i), key);
//     }

//     return Padded;
// }

// uint8_t* Encrypt::ECBDecrypt(uint8_t* ciphertext, uint64_t size, uint8_t* key)
// {
//     AES Aes;
    
//     for(uint64_t i = 0; i < size; i+=16)
//     {
//         //* Should overwrite padded to contain encrypted values, 16 bytes at a time
//         Aes.Decrypt((ciphertext+i), key);
//     }

//     //* Creates array Padded with a NewSize that is divisible by 16
//     //! Padded is a dynamically allocated array
//     uint8_t* UnPadded = InvPadArr(ciphertext, size);
//     uint32_t NewSize = size - (16-(size%16));

//     //! Unknown length of UnPadded
//     return UnPadded;
// }
