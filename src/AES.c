#include "../include/AES.h"
#include <stdio.h>

// We need an API function to take data of X size, and convert it to encrypted data of X size.
// The sizes match, so they can be the same variable.
// So, we will make the function change the X size array itself.
//* Any "pre-generated" arrays will have initializer functions to fill them.

void AESEnc(uint8_t* Plaintext, const uint8_t* Key)
{
    //! NOTE, ALL CURRENT STEPS ARE FOR 128-BIT. DOUBLE CHECK AND CORRECT FOR 256-BIT.
    // Data will be modified. Key wont
    // Key will be 256-bit cause why not?
    // Maybe make all 3? 
    // 256 first tho, keep in mind portability for functions

    //? Fill state sideways
    uint8_t State[16] = 
    {
        Plaintext[0], Plaintext[4], Plaintext[8], Plaintext[12],
        Plaintext[1], Plaintext[5], Plaintext[9], Plaintext[13],  
        Plaintext[2], Plaintext[6], Plaintext[10], Plaintext[14],  
        Plaintext[3], Plaintext[7], Plaintext[11], Plaintext[15]
    };

    //? Key expansion (check for differences in 128-bit to 256-bit)
    //* KeyExpand function

    //? Xor first Key
    //* XorKey function

    //? Rounds
    //* SubBytes function
    //* ShiftRows function
    //* MixColumns function

    //? Final round without Mix Columns

    //? Deallocate KeyExpansion (or make it static/set size)

    //? Fill Data (reverse) sideways
    //* Reverse State init, but use regular Plaintext[i] = State[j] declaration, 16 of em.
    
    return;
}

void AESDec(uint8_t* Ciphertext, const uint8_t* Key)
{
    //? Fill state sideways

    //? Key expansion (same)

    //? Xor (last?) key

    //? Rounds (seemingly in reverse, both in i and functions)

    //? Last round without mix columns, same reverse

    //? Deallocate KeyExpansion (or make it static/set size)

    //? Fill Data (reverse) sideways

    return;
}

uint32_t AESKeyGen()
{
    union Key
    {
        uint32_t Key256;
        // uint24_t (which does not exist)
        uint16_t Key128;
    };
    // Seed data?
    // Enum for bit size?
    
    // Switch size or basic math calc w/ enum
    // Generate key of Enum size (128, 196, 256)

    // Return union? 
    return 0;
}

// Static functions will be necessary, along with defines
// Eventually, we will need encryption methods (ECB, CBC), which will go into another file (along with more cryptography such as md5)
// I am NOT making AES sidechannel secure, not happening.