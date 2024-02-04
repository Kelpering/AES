#include "../include/AES.h"
#include "../include/AESPrivate.h"
#include <stdio.h>

// We need an API function to take data of X size, and convert it to encrypted data of X size.
// The sizes match, so they can be the same variable.
// So, we will make the function change the X size array itself.
//* Any "pre-generated" arrays will have initializer functions to fill them.

void AESEnc(uint8_t* Plaintext, const uint8_t* Key)
{
    //! This is unnecessary and inefficient
    InitSbox();
    //? Fill state sideways
    uint8_t State[16] = 
    {
        Plaintext[0], Plaintext[4], Plaintext[8], Plaintext[12],
        Plaintext[1], Plaintext[5], Plaintext[9], Plaintext[13],  
        Plaintext[2], Plaintext[6], Plaintext[10], Plaintext[14],  
        Plaintext[3], Plaintext[7], Plaintext[11], Plaintext[15]
    };

    //? Key expansion
    uint32_t* EKey = KeyExpansion256(Key);

    //? Xor first Key
    AddRoundKey(State, (EKey + 0));

    //? Rounds
    for (int i = 1; i < 14; i++)
    {
        SubBytes(State);
        ShiftRows(State);
        MixColumns(State);
        AddRoundKey(State, (EKey+(i*4)));
    }

    //? Final round without Mix Columns
    SubBytes(State);
    ShiftRows(State);
    AddRoundKey(State, (EKey+(14*4)));


    //? Clear and de-allocate Expanded Key
    for (int i = 0; i < 60; i++)
        EKey[i] = 0;
    free(EKey);

    //? Fill Data (reverse) sideways
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
    //! This is inefficient
    InitInvSBox();
    //? Fill state sideways
    uint8_t State = 
    {
        Ciphertext[0], Ciphertext[4], Ciphertext[8], Ciphertext[12],
        Ciphertext[1], Ciphertext[5], Ciphertext[9], Ciphertext[13],
        Ciphertext[2], Ciphertext[6], Ciphertext[10], Ciphertext[14],
        Ciphertext[3], Ciphertext[7], Ciphertext[11], Ciphertext[15]
    };
    //? Key expansion (same)

    //? Xor (last?) key

    //? Rounds (seemingly in reverse, both in i and functions)

    //? Last round without mix columns, same reverse

    //? Deallocate KeyExpansion (or make it static/set size)

    //? Fill Data (reverse) sideways
    Ciphertext[0] = State[0];
    Ciphertext[1] = State[4];
    Ciphertext[2] = State[8];
    Ciphertext[3] = State[12];
    Ciphertext[4] = State[1];
    Ciphertext[5] = State[5];
    Ciphertext[6] = State[9];
    Ciphertext[7] = State[13];
    Ciphertext[8] = State[2];
    Ciphertext[9] = State[6];
    Ciphertext[10] = State[10];
    Ciphertext[11] = State[14];
    Ciphertext[12] = State[3];
    Ciphertext[13] = State[7];
    Ciphertext[14] = State[11];
    Ciphertext[15] = State[15];

    return;
}

uint32_t AESKeyGen256()
{
    // Seed data
    // Generate key of size 256-bit (32 bytes)

    // Return union? 
    return 0;
}

// Static functions will be necessary, along with defines
// Eventually, we will need encryption methods (ECB, CBC), which will go into another file (along with more cryptography such as md5)
// I am NOT making AES sidechannel secure, not happening.

static uint32_t* KeyExpansion256(uint8_t* Key)
{
    //? Malloc a 256-bit expanded key (constant size).
    uint32_t* EKey = malloc(240);

    //? First 8 words are the cipherkey, set as bytes.
    for (int i = 0; i < 8*4; i++)
        ((uint8_t*) EKey)[i] = Key[i];
    
    //? Generate 60 words (15 keys), first 4 set.
    //* RCON is the round constant, set to initial value of 1.
    uint8_t RCON = 1;
    for (int i = 8; i < (15*4); i++)
    {
        //* Prev is the last word generated.
        //* Prev is a seperate memory pointer from w[], to allow for memory manipulation without affecting previously generated keys.
        uint32_t Prev = *(EKey + i - 1);

        //? Transformes specific bytes in w[i].
        if (i % 8 == 0)
        {
            RotWord(&Prev);
            SubWord(&Prev);
            //* RCON is XOR'd directly because of Prev's endianness
            Prev ^= RCON;
            RCON = GMul(RCON, 0x02);
        }
        else if ((i+4)%8 == 0)
        {
            SubWord(&Prev);
        }

        EKey[i] = EKey[i-8] ^ Prev;
    }

    //! Expanded key must be freed at the end of the AES run.
    return EKey;
}

static void RotWord(uint8_t* Word)
{
    uint8_t Temp = Word[0];
    Word[0] = Word[1];
    Word[1] = Word[2];
    Word[2] = Word[3];
    Word[3] = Temp;
    return;
}

static void SubWord(uint8_t* Word)
{
    Word[0] = SBox[Word[0]];
    Word[1] = SBox[Word[1]];
    Word[2] = SBox[Word[2]];
    Word[3] = SBox[Word[3]];
    return 0;
}

static void AddRoundKey(uint8_t* State, const uint8_t* EKey)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[j*4+i] ^= EKey[i*4+j];
    return;
}

static void SubBytes(uint8_t* State)
{
    //! Double check later
    for (int i = 0; i < 16; i++)
        State[i] = SBox[State[i]];
    return;
}

static void InvSubBytes(uint8_t* State)
{

    return;
}

static void ShiftRows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+j] = Temp[i*4+(j+i)%4];
    return;
}

static void InvShiftRows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+(j+i)%4] = Temp[i*4+j];
    return;
}

static void MixColumns(uint8_t* State)
{
    // Stores State while the column is being altered.
    uint8_t Temp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            Temp[j] = State[j*4+i];

        State[0*4+i] = GMul(Temp[0], 0x02) ^ GMul(Temp[1], 0x03) ^ Temp[2] ^ Temp[3];
        State[1*4+i] = Temp[0] ^ GMul(Temp[1], 0x02) ^ GMul(Temp[2], 0x03) ^ Temp[3];
        State[2*4+i] = Temp[0] ^ Temp[1] ^ GMul(Temp[2], 0x02) ^ GMul(Temp[3], 0x03);
        State[3*4+i] = GMul(Temp[0], 0x03) ^ Temp[1] ^ Temp[2] ^ GMul(Temp[3], 0x02);
    }
    return;
}

static void InvMixColumns(uint8_t* State)
{

    return;
}

static uint8_t SBoxFunc(uint8_t Byte)
{
    //* Inverse of byte in GF(2^8)
    uint8_t Inv = GInv(Byte);

    //! Double check how this works
    Byte = Inv ^ \
    ROTL8(Inv, 1) ^ \
    ROTL8(Inv, 2) ^ \
    ROTL8(Inv, 3) ^ \
    ROTL8(Inv, 4) ^ \
    0x63;
    
    return Byte;
}

static uint8_t InvSBoxFunc(uint8_t byte)
{

    byte = ROTL8(byte, 1) ^ ROTL8(byte, 3) ^ ROTL8(byte, 6) ^ 0x05;
/* byte = (byte ROTL 1) ^ (Byte ROTL 3) ^ (Byte ROTL 6) ^ (0x05)
    byte = 
    ROTL8(byte, 1) ^ 
    ROTL8(byte, 3) ^ 
    ROTL8(byte, 6) ^ 
    0x05;
*/
    //* Returns the multiplicative inverse of the result within the Galois Field GF(2^8)
    return GInv(byte);
}

void InitSbox()
{
    for (int i = 0; i < 256; i++)
        SBox[i] = SBoxFunc(i);
    return;
}

void InitInvSBox()
{
    for (int i = 0; i < 256; i++)
        InvSBox[i] = InvSBoxFunc(i);
    return;
}

static uint8_t GMul(uint8_t x, uint8_t y)
{
	uint8_t p = 0;
	uint8_t carry = 0;
    for (int i = 0; i < 8; i++)
	{
		//* If the first bit of Y is a 1, add x to p
		if (y&1)
            p ^= x;

        //* Set carry to 1 if x's 7th bit is 1
        carry = x & 0x80;
        
        x <<= 1;
        y >>= 1;

        //* If carry was set, add carry byte (0x1B)
        if (carry)
            x ^= 0x1B;
	}
    return p;
}

static uint8_t GInv(uint8_t a)
{
    //* Uses combinations of variables to multiply a by itself exactly 254 times.
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
