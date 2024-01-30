#include "../include/AES.h"
#include <stdio.h>

// We need an API function to take data of X size, and convert it to encrypted data of X size.
// The sizes match, so they can be the same variable.
// So, we will make the function change the X size array itself.
//! NOTE, ALL CURRENT STEPS ARE FOR 128-BIT. DOUBLE CHECK AND CORRECT FOR 256-BIT.
//* Any "pre-generated" arrays will have initializer functions to fill them.

void AESEnc(uint8_t* Data, const uint8_t* Key)
{
    // Data will be modified. Key wont
    // Key will be 256-bit cause why not?
    // Maybe make all 3? 
    // 256 first tho, keep in mind portability for functions

    //? Fill state sideways

    //? Key expansion (check for differences in 128-bit to 256-bit)

    //? Xor first Key

    //? Rounds

    //? Final round without Mix Columns

    //? Deallocate KeyExpansion (or make it static/set size)

    //? Fill Data (reverse) sideways

    return;
}

void AESDec(uint8_t* Data, const uint8_t* Key)
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