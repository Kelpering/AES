#include <stdint.h>
#include <iostream>

// Whether to use the SBox func or the SBox array
#define _SBox_Func_ true

/**
 * A class that handles AES-128 functions. Does not include padding, only accepts 16 bytes per run.
 * 
 * 
*/
class AES
{
    private:
        #if _SBox_Func_
        uint8_t SBox(uint8_t byte);
        #else
        const uint8_t sbox[256] = 
        {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
        };
        #endif
        uint8_t GMul(uint8_t x, uint8_t y);
        uint8_t GInv(uint8_t x);

        uint8_t Rcon(uint8_t iter);
        uint8_t* KeyExpansion(uint8_t Key[16]);
        
        void SubBytes(uint8_t State[16]);
        void ShiftRows(uint8_t State[16]);
        void MixColumns(uint8_t State[16]);
        void AddRoundKey(uint8_t State[16], uint8_t Key[16]);

    public:
        uint8_t* Encrypt(uint8_t plaintext[16], uint8_t key[16]);
        uint8_t* Decrypt(uint8_t ciphertext[16], uint8_t key[16]);

};


/**
 * Encrypts a block of 16 bytes with a key of 16 bytes using the AES protocol. 
 * 
 *! @warning Returns allocated array, user is expected to deallocate this array.
 * 
 * @param *plaintext Pointer to a 16 byte array containing the plaintext to encrypt.
 * @param *key Pointer to a 16 byte array containing the key to encrypt with.
 * 
 * @returns Pointer to a newly allocated 16 byte array containing the ciphertext. User is expected to deallocate this array.
*/
uint8_t* AES::Encrypt(uint8_t plaintext[16], uint8_t key[16])
{
    //? Initialize State
    uint8_t* State = new uint8_t[16];   //* Allocate a 16 byte array (State)

    int count = 0;      //* Temp count var
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            //* Set State "Sideways", if 4x4, do (0,0) (1,0)... instead of (0,0) (0,1)...
            State[count] = plaintext[j*4+i];
            count++;
        }
    }

    //? Initialize RoundKeys
    uint8_t* RoundKey = KeyExpansion(key);

    //* XOR first RoundKey before the rounds begin.
    AddRoundKey(State, (RoundKey + (0)));

    //? Rounds
    for (int i = 1; i < 10; i++)
    {
        //* Substitute all bytes on State
        SubBytes(State);
        //* Shift the rows on State
        ShiftRows(State);
        //* Mix the columns on State
        MixColumns(State);
        //* XOR the round key corresponding to the round.
        AddRoundKey(State, (RoundKey + (16*i)));
    }
    //* Run the final round without MixColumns
    SubBytes(State);
    ShiftRows(State);
    AddRoundKey(State, (RoundKey + (16*10)));

    //* Deallocate RoundKey
    delete[] RoundKey;

    //! Returns a dynamically allocated array.
    return State;
}

/**
 * Decrypts a block of 16 bytes with a key of 16 bytes using the AES protocol. 
 * 
 * @param *plaintext Pointer to a 16 byte array containing the ciphertext to decrypt.
 * @param *key Pointer to a 16 byte array containing the key to decrypt with.
 * 
 * @returns Pointer to a newly allocated 16 byte array containing the decrypted plaintext. User is expected to deallocate this array.
*/
uint8_t* AES::Decrypt(uint8_t ciphertext[16], uint8_t key[16])
{

    return 0;
}


/**
 * Rotates an 8 bit number x left by shift. 
 * 
 * @param x Number to shift
 * @param shift bits to shift by
 * 
 * @returns x rotated shift bits left
*/
#define ROTL8(x, shift) (((uint8_t) x << shift) | ((uint8_t) x >> 8 - shift))

/**
 * Multiplies 2 numbers within the Galois Field GF(2^8), also known as the Rjindael finite field.
 * 
 * @returns (x * y) within GF(2^8).
*/
uint8_t AES::GMul(uint8_t x, uint8_t y)
{
    uint8_t p = 0;
    uint8_t carry;
    for(int i = 0; i < 8; i++)
    {
        if (y & 1)     //* if the first bit of y is 1, (G Add) p and x.
            p ^= x;
        carry = x & 0x80;

        x = x << 1;         //* Multiplies by x.
        y = y >> 1;         //* Divides by x.

        if (carry)
             x ^= 0x1b;
    }

    return p;
}

/**
 * Gives the multiplicative inverse of a number within the Galois Field GF(2^8).
 * 
 * @param a Number to find the inverse of.
 * 
 * @returns b where (a * b) = 1 within the Galois Field GF(2^8).
*/
uint8_t AES::GInv(uint8_t a)
{
    //! Works, figure out how later
    uint8_t b = GMul(a,a);
    uint8_t c = GMul(a,b);
            b = GMul(c,c);
            b = GMul(b,b);
            c = GMul(b,c);
            b = GMul(b,b);
            b = GMul(b,b);
            b = GMul(b,c);
            b = GMul(b,b);
            b = GMul(a,b);
    return GMul(b,b);
}

/**
 * Manually calculates a single SBox value. Less efficient compared to a lookup table.
 * 
 * @param byte A single byte to convert
 * 
 * @returns The converted byte
*/
uint8_t AES::SBox(uint8_t byte)
{
    if(byte == 0)   // Special case '0'
    {
        byte = 0x63;
        return byte;
    }

    //* Multiplicative inverse of a number within the Galois Field GF(2^8)
    uint8_t iByte = GInv(byte);

    //* State[i] = (iByte) GAdd (iByte ROTL 1) GAdd (iByte ROTL 2) GAdd (iByte ROTL 3) GAdd (iByte ROTL 4)
    byte = iByte ^ 
    ROTL8(iByte, 1) ^ 
    ROTL8(iByte, 2) ^ 
    ROTL8(iByte, 3) ^ 
    ROTL8(iByte, 4) ^ 
    0x63;

    return byte;
}

/**
 * Substitutes bytes either via a function (slow), or an array (fast).
 * Alter this behavior with a #define directive.
 * 
 * !Overwrites to state during operation.
*/
void AES::SubBytes(uint8_t State[16])
{
    for(int i = 0; i < 16; i++)
    {
        #if _SBox_Func_
        State[i] = SBox(State[i]);
        #else
        State[i] = sbox[State[i]];
        #endif
    }
    return;
}

/**
 * Shifts rows of State a by an offset dependant on the row.
 * 
 * !Overwrites to state during operation.
*/
void AES::ShiftRows(uint8_t State[16])
{
    uint8_t Temp[16];
    for(int i = 0; i < 16; i++)
    {
        Temp[i] = State[i];
    }
    for(int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            State[i*4+j] = Temp[i*4+(j+i)%4];
        }
    }
    return;
}

/**
 * Mixes columns of State via matrix multiplication.
 * 
 *! Overwrites directly to state during operation.
*/
void AES::MixColumns(uint8_t State[16])
{
    for (int Column = 0; Column < 4; Column++)
    {
        uint8_t Temp[4];
        for (int i = 0; i < 4; i++)
        {
            Temp[i] = State[i*4+Column];
        }
        State[0*4+Column] = GMul(2, Temp[0]) ^ GMul(3, Temp[1]) ^ Temp[2] ^ Temp[3];
        State[1*4+Column] = Temp[0] ^ GMul(2, Temp[1]) ^ GMul(3, Temp[2]) ^ Temp[3];
        State[2*4+Column] = Temp[0] ^ Temp[1] ^ GMul(2, Temp[2]) ^ GMul(3, Temp[3]);
        State[3*4+Column] = GMul(3, Temp[0]) ^ Temp[1] ^ Temp[2] ^ GMul(2, Temp[3]);
    }
    return;
}

/**
 * Adds a round key to State, byte by byte.
 * 
 *! Overwrites to state during operation.
*/
void AES::AddRoundKey(uint8_t State[16], uint8_t* Key)
{
    //* Each set of 4 have to be XOR'd with a column of the state.
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            State[i*4+j] ^= Key[j*4+i];
        }
    }
    return;
}

/**
 * Calculates the Round Constant for the current iteration.
 * 
 * @param iter The current iteration to be calculated for
 * 
 * @returns The Round Constant
*/
uint8_t AES::Rcon(uint8_t iter)
{
    iter = iter-1;

    if (iter == 0)
        return 0x01;

    uint8_t result = 0x02;

    for (int i = 0; i < iter - 1; i++)
    {
        result = GMul(result, 0x02);
    }
    
    return result;
}

/**
 * Expands the original key to use for each round.
 * 
 * Returns a pointer to a newly allocated array of keys.
 *! Array must be destroyed at a later point.
*/
uint8_t* AES::KeyExpansion(uint8_t Key[16])
{
    //* Allocates RoundKey which is 16 bytes (1 key) times 11 (11 round keys).
    uint8_t* RoundKey = new uint8_t[16*11];

    //* First RoundKey is just the key
    for (int i = 0; i < 16; i++)
    {
        RoundKey[i] = Key[i];
    }

    //* 11 rounds * 4 words , we already did one.
    for (int i = 4; i < 44; i++)
    {
        // Last iterations * 4 (each iteration is 4 bytes) + offset
        uint8_t temp[4] = 
        {
            //i selects column, + x selects row
            RoundKey[(i-1)*4+0], //Selects next 4
            RoundKey[(i-1)*4+1], 
            RoundKey[(i-1)*4+2],
            RoundKey[(i-1)*4+3]
        };

        //* If new round key
        if (i%4 == 0)
        {
            //* RotWord()
            uint8_t rot = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = rot;

            //* SubWord()
            temp[0] = SBox(temp[0]);
            temp[1] = SBox(temp[1]);
            temp[2] = SBox(temp[2]);
            temp[3] = SBox(temp[3]);

            //* Rcon()
            temp[0] = temp[0] ^ Rcon(i/4);
        }

        //* XOR a word (4 bytes) together
        RoundKey[i*4+0] = (RoundKey[(i-4)*4+0] ^ temp[0]);
        RoundKey[i*4+1] = (RoundKey[(i-4)*4+1] ^ temp[1]);
        RoundKey[i*4+2] = (RoundKey[(i-4)*4+2] ^ temp[2]);
        RoundKey[i*4+3] = (RoundKey[(i-4)*4+3] ^ temp[3]);
    }
    return RoundKey;
}