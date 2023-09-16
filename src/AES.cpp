#include "AES.h"

/**
 * Encrypts a block of 16 bytes with a key of 16 bytes using the AES protocol. 
 * 
 *! @warning Overwrites plaintext.
 * 
 * @param *plaintext Pointer to a 16 byte array containing the plaintext to encrypt.
 * @param *key Pointer to a 16 byte array containing the key to encrypt with.
*/
void AES::Encrypt(uint8_t plaintext[16], uint8_t key[16])
{
    //? Initialize State
    uint8_t State[16] = 
    {
        plaintext[0], plaintext[4], plaintext[8], plaintext[12],
        plaintext[1], plaintext[5], plaintext[9], plaintext[13],
        plaintext[2], plaintext[6], plaintext[10], plaintext[14],
        plaintext[3], plaintext[7], plaintext[11], plaintext[15]
    };
    

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

    //! Overwrites plaintext.
    plaintext[0]  = State[0];
    plaintext[4]  = State[1];
    plaintext[8]  = State[2];
    plaintext[12] = State[3];
    plaintext[1]  = State[4];
    plaintext[5]  = State[5];
    plaintext[9]  = State[6];
    plaintext[13] = State[7];
    plaintext[2]  = State[8];
    plaintext[6]  = State[9];
    plaintext[10] = State[10];
    plaintext[14] = State[11];
    plaintext[3]  = State[12];
    plaintext[7]  = State[13];
    plaintext[11] = State[14];
    plaintext[15] = State[15]; 
    return;
}

/**
 * Decrypts a block of 16 bytes with a key of 16 bytes using the AES protocol. 
 * 
 * @warning Overwrites ciphertext
 * 
 * @param *plaintext Pointer to a 16 byte array containing the ciphertext to decrypt.
 * @param *key Pointer to a 16 byte array containing the key to decrypt with.
*/
void AES::Decrypt(uint8_t ciphertext[16], uint8_t key[16])
{
    //? Initialize State
    uint8_t State[16] = 
    {
        ciphertext[0], ciphertext[4], ciphertext[8], ciphertext[12],
        ciphertext[1], ciphertext[5], ciphertext[9], ciphertext[13],
        ciphertext[2], ciphertext[6], ciphertext[10], ciphertext[14],
        ciphertext[3], ciphertext[7], ciphertext[11], ciphertext[15]
    };

    //? Initialize RoundKeys
    uint8_t* RoundKey = KeyExpansion(key);

    //* XOR first RoundKey before the rounds begin.
    AddRoundKey(State, (RoundKey + (16*10)));

    //? Rounds
    for (int i = 10; i > 1; i--)
    {
        
        //* UnShift the rows on State
        InvShiftRows(State);
        //* UnSubstitute all bytes on State
        InvSubBytes(State);
        //* XOR the round key corresponding to the round.
        AddRoundKey(State, (RoundKey + (16 * (i - 1))));
        //* UnMix the columns on State
        InvMixColumns(State);
    }
    //* Run the final round without MixColumns
    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State, (RoundKey + (0)));

    //* Deallocate RoundKey
    delete[] RoundKey;

    //! Overwrites plaintext.
    ciphertext[0]  = State[0];
    ciphertext[4]  = State[1];
    ciphertext[8]  = State[2];
    ciphertext[12] = State[3];
    ciphertext[1]  = State[4];
    ciphertext[5]  = State[5];
    ciphertext[9]  = State[6];
    ciphertext[13] = State[7];
    ciphertext[2]  = State[8];
    ciphertext[6]  = State[9];
    ciphertext[10] = State[10];
    ciphertext[14] = State[11];
    ciphertext[3]  = State[12];
    ciphertext[7]  = State[13];
    ciphertext[11] = State[14];
    ciphertext[15] = State[15]; 
    return;
}


/**
 * Rotates an 8 bit number x left by shift. 
 * 
 * @param x Number to shift
 * @param shift bits to shift by
 * 
 * @returns x rotated shift bits left
*/
#define ROTL8(x, shift) (((uint8_t) x << shift) | ((uint8_t) x >> (8 - shift)))

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

    //* byte = (iByte) GAdd (iByte ROTL 1) GAdd (iByte ROTL 2) GAdd (iByte ROTL 3) GAdd (iByte ROTL 4)
    byte = iByte ^ 
    ROTL8(iByte, 1) ^ 
    ROTL8(iByte, 2) ^ 
    ROTL8(iByte, 3) ^ 
    ROTL8(iByte, 4) ^ 
    0x63;

    return byte;
}

/**
 * Manually calculates a single Inverse SBox value. Less efficient compared to a lookup table.
 * 
 * @param byte A single byte to convert
 * 
 * @returns The converted byte
*/
uint8_t AES::InvSBox(uint8_t byte)
{

    //* byte = (byte ROTL 1) ^ (Byte ROTL 3) ^ (Byte ROTL 6) ^ (0x05)
    byte = 
    ROTL8(byte, 1) ^ 
    ROTL8(byte, 3) ^ 
    ROTL8(byte, 6) ^ 
    0x05;
    
    //* Returns the multiplicative inverse of the result within the Galois Field GF(2^8)
    return GInv(byte);
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
        State[i] = SBox(State[i]);
    }
    return;
}

/**
 * Runs Substitute in reverse via a function.
 * 
 * !Overwrites to state during operation.
*/
void AES::InvSubBytes(uint8_t State[16])
{
    for(int i = 0; i < 16; i++)
    {
        State[i] = InvSBox(State[i]);
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
 * Shifts rows of State a by an offset dependant on the row, opposite direction of ShiftRows().
 * 
 * !Overwrites to state during operation.
*/
void AES::InvShiftRows(uint8_t State[16])
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
            State[i*4+(j+i)%4] = Temp[i*4+j];
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
 * Unmixes columns of State via matrix multiplication, reversing MixColumns().
 * 
 *! Overwrites directly to state during operation.
*/
void AES::InvMixColumns(uint8_t State[16])
{
    for (int Column = 0; Column < 4; Column++)
    {
        uint8_t Temp[4];
        for (int i = 0; i < 4; i++)
        {
            Temp[i] = State[i*4+Column];
        }
        State[0*4+Column] = GMul(0x0e, Temp[0]) ^ GMul(0x0b, Temp[1]) ^ GMul(0x0d, Temp[2]) ^ GMul(0x09, Temp[3]);
        State[1*4+Column] = GMul(0x09, Temp[0]) ^ GMul(0x0e, Temp[1]) ^ GMul(0x0b, Temp[2]) ^ GMul(0x0d, Temp[3]);
        State[2*4+Column] = GMul(0x0d, Temp[0]) ^ GMul(0x09, Temp[1]) ^ GMul(0x0e, Temp[2]) ^ GMul(0x0b, Temp[3]);
        State[3*4+Column] = GMul(0x0b, Temp[0]) ^ GMul(0x0d, Temp[1]) ^ GMul(0x09, Temp[2]) ^ GMul(0x0e, Temp[3]);
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
