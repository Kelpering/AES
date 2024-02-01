#include "../include/AES.h"
#include <stdio.h>

// These might be wrong. If multiplication is off, check these first.
#define XTimes(X)   (uint8_t) ((X<<1) ^ (((X>>7) & 1) * (0x1B)))
#define GMul(X,Y)   (((Y&1) * X ) ^ \
                    ((Y>>1&1) * XTimes(X)) ^ \
                    ((Y>>2&1) * XTimes(XTimes(X))) ^ \
                    ((Y>>3&1) * XTimes(XTimes(XTimes(X)))) ^ \
                    ((Y>>4&1) * XTimes(XTimes(XTimes(XTimes(X))))))


// We need an API function to take data of X size, and convert it to encrypted data of X size.
// The sizes match, so they can be the same variable.
// So, we will make the function change the X size array itself.
//* Any "pre-generated" arrays will have initializer functions to fill them.

static uint8_t SBox[256];

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

    //! Multiplication playground
    printf("GMUL: __%X__\n", GMul(0x57, 0x13));

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

    Plaintext[0] = State[0];
    Plaintext[1] = State[4];
    Plaintext[2] = State[8];
    Plaintext[3] = State[12];
    Plaintext[4] = State[1];
    Plaintext[5] = State[5];
    Plaintext[6] = State[9];
    Plaintext[7] = State[13];
    Plaintext[8] = State[2];
    Plaintext[9] = State[6];
    Plaintext[10] = State[10];
    Plaintext[11] = State[14];
    Plaintext[12] = State[3];
    Plaintext[13] = State[7];
    Plaintext[14] = State[11];
    Plaintext[15] = State[15];
    
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

static void KeyExpansion(uint8_t* Key)
{

    return;
}

static void XorState(uint8_t* State, const uint8_t* Key)
{
    for (int i = 0; i < 16; i++)
    {
        // The key is seen sideways for some reason
        // Might be useful in the future for KeyExpand, if this is repeated.
    }
    return;
}

static void SubBytes(uint8_t* State)
{
    // This will use an SBox.
    // These SBox values in the array will be initialized.
    return;
}

static void InvSubBytes(uint8_t* State)
{

    return;
}

static void ShiftRows(uint8_t* State)
{

    return;
}

static void InvShiftRows(uint8_t* State)
{

    return;
}

static void MixColumns(uint8_t* State)
{

    return;
}

static void InvMixColumns(uint8_t* State)
{

    return;
}

static void InitSbox()
{
    // Reorder these functions (attempt to place all in AES.h)
    return;
}

// GAdd is a simple XOR
// GMul must be implemented with XTimes
/*
static inline uint8_t XTimes(uint8_t X)
{
    return (X << 1) ^ ((X>>7) * (0b00011011));
}
*/


/*
static inline uint8_t GMul(uint8_t X, uint8_t Y)
{
    return (((Y & 1) * X) ^
    ((Y>>1 & 1) * XTimes(X)) ^
    ((Y>>2 & 1) * XTimes(XTimes(X))) ^
    ((Y>>3 & 1) * XTimes(XTimes(XTimes(X)))) ^
    ((Y>>4 & 1) * XTimes(XTimes(XTimes(XTimes(X))))));
}

static inline uint8_t GInv(uint8_t X)
{
    // Inverse or swap with InitSBox
    return X;
}
*/
