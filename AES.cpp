// This program will use the AES-128 standard

// Nb is number of Columns, standard here is 4
// Nk is number of words in key, 128bit standard here is 4
// Nr is number of rounds, 128bit standard here is 10

// Dev Log:
/*
    Runs bad, currently on InvMixColumn
    Plan:
    - Finish program, test with online AES-128.
    - Add block padding & ECB to divide longer data into 128 bit blocks.
    - Refactor code to be not absolute hot garbage.
    - Add CBC to make true AES implementation
    - Make RSA implementation later. (Combine with this program)
    Unlikely:
    - Implement optimizations.
    - Learn how AES actually works
    - New program: AES-256
    - Make class similar to other one I saw (github project)
    - Add s-box calculations            (Small file size spectrum)
    - Add all hard coded calculations   (Large file size spectrum)
    - Assembly optimizations?? CPU optimizations??  (This is not happening)

*/

#include <iostream>     // Used for printing.
#include <iomanip>      // Used for debug state, prints hex.

using namespace std;

const unsigned char sbox[16][16] = // [x] [y]
{
{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

const unsigned char inv_sbox[16][16] = 
{
{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

void ExpandKey(unsigned char Key[16], unsigned char KeySchedule[44][16]);

void AddRoundKey(unsigned char State[4][4], unsigned char Key[16]);
void SubByte(unsigned char State[4][4]);
void ShiftRow(unsigned char State[4][4]);
void MixColumn(unsigned char State[4][4]);

void EncryptBlock(unsigned char In[16], unsigned char Key[16], unsigned char Out[16]);

void InvSubByte(unsigned char State[4][4]);
void InvShiftRow(unsigned char State[4][4]);
void InvMixColumn(unsigned char State[4][4]);

void DecryptBlock(unsigned char In[16], unsigned char Key[16], unsigned char Out[16]);

void PrintState(unsigned char State[4][4]);
void PrintKey(unsigned char Key[16]);

int main()
{
    // In is regular left to right, top to bottom read. Convert to block in EncryptBlock()
    unsigned char In[16] =      
    {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    // Key is in left to right, top to bottom format with workarounds added for each Key Func()
    unsigned char Key[16]    = 
    {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char Out[16];
    
    // TODO: Remove unecessary comments, Add more documentation comments

    // TODO: Unit test, All signs point to Encrypt & Decrypt functions being successful.
    // TODO: After unit test, implement padding and ECB
    // TODO: After ECB, Implement CBC
    // TODO: After unit testing CBC, Revise code thoroughly
    // TODO: After revise, implement AES-256

    PrintKey(In);
    cout << endl;

    EncryptBlock(In, Key, Out);     // Encrypts block

    DecryptBlock(Out, Key, Out);    // Decrypts block
    PrintKey(Out);
    return 0;
}

unsigned char GMul(unsigned char a, unsigned char b)
{
    unsigned char p = 0, i = 0, hbs = 0;

    for (i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }

        hbs = a & 0x80;
        a <<= 1;
        if (hbs)
        {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return (p);
}

void SubWord(unsigned char Word[4])
{
    for (int i = 0; i < 4; i++)
    {
        unsigned char x = Word[i] & 0b00001111;    // First 4
        unsigned char y = Word[i] >> 4;            // Last  4
        //Apply S-box to all 4 bytes
        Word[i] = sbox[y][x];
    }
}

void RotWord(unsigned char Word[4])
{
    unsigned char temp[4];
    for (int i = 0; i < 4; i++)
    {
        temp[i] = Word[(i+5)%4];
    }
    for (int i = 0; i < 4; i++)
    {
        Word[i] = temp[i];
    }
}

    // Remake later, all this func does is 2^i within the Galios Field.
unsigned char rcon(unsigned char in) 
{
        unsigned char c=1;
        if(in == 0)  
                return 0; 
        while(in != 1) {
		unsigned char b;
		b = c & 0x80;
		c <<= 1;
		if(b == 0x80) {
			c ^= 0x1b;
		}
                in--;
        }
        return c;
}

void ExpandKey(unsigned char Key[16], unsigned char KeySchedule[11][16])
{
    unsigned char TempSchedule[176];
    unsigned char Temp[4];
    int i = 1;
    int c;

    for (c = 0; c < 16; c++)                  // 0-15 bytes in TempSchedule
    {        
        TempSchedule[c] = Key[c];
    }

    while (c < 176)
    {
        // Assign Temp to last 4 COLUMN bytes
        for (int j = 0; j < 4; j++)
        {
            Temp[j] = TempSchedule[c-4+j];
        }
        //cout << endl;

        // Modify Temp if new key
        if ( c % 16 == 0)                       // Every 0th-4th byte in every key (0-15 bytes)
        {
            RotWord(Temp);
            SubWord(Temp);
            Temp[0] ^= rcon(i);
            i++;
        }

        // Take previous word (Temp) and xor with word 4 words ago (4x4 = 16 bytes ago)
        // Every start of a key (c%16==0) uses previous byte with RotWord, SubWord, and rcon

        // Assign new word to Schedule.
        for (int j = 0; j < 4; j++)
        {
            TempSchedule[c] = Temp[j] ^ TempSchedule[c-16];
            c++;
        }
    }

    int count = 0;
    for (int i = 0; i < 11; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            KeySchedule[i][j] = TempSchedule[count];
            count++;
        }
    }

}

// Modifies State to ( State[i] XOR Key[i] )
void AddRoundKey(unsigned char State[4][4], unsigned char Key[16]) 
{
    unsigned int count = 0;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            State[i][j] = State[i][j] ^ Key[i+(j*4)];
            count++;
        }
    }
    return;
}

void SubByte(unsigned char State[4][4])
{

    // Loop entire State[][]
    // For each byte, split into x & y for Sbox
    // Replace State[curr][curr] with sbox[x][y]
    // End Loop
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            unsigned char x = State[i][j] & 0b00001111;      // First 4    
            unsigned char y= State[i][j] >> 4;               // Last  4 
            State[i][j] = sbox[y][x];
            //Split hex state into 2, 4bit nums or 2 individual hex values.
        }
    }
    return;
}

void InvSubByte(unsigned char State[4][4])
{

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            unsigned char x = State[i][j] & 0b00001111;    // First 4
            unsigned char y= State[i][j] >> 4;               // Last  4
            State[i][j] = inv_sbox[y][x];
            //Split hex state into 2, 4bit nums or 2 individual hex values.
        }
    }
    return;
}

void ShiftRow(unsigned char State[4][4])
{
    //Shift by row, 0 shift left, 1 shift left, 2 shift left, 3 shift left
    /* replace bits with bytes in practice.
    1 0 0 1  =    1 0 0 1
    0 0 1 0  >    0 1 0 0
    1 1 0 1  >>   0 1 1 1
    0 1 0 1  >>>  1 0 1 0
    */
    unsigned char temp[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i][j] = State[i][(i+j)%4];
        }
        for (int j = 0; j < 4; j++)
        {
            State[i][j] = temp[i][j];
        }
        
    }
    return;
}

void InvShiftRow(unsigned char State[4][4])     // Requires testing
{
    unsigned char temp[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i][(i+j)%4] = State[i][j];
        }
        for (int j = 0; j < 4; j++)
        {
            State[i][j] = temp[i][j];
        }
    }
    return;
}

void MixColumn(unsigned char State[4][4])
{

    unsigned char a[4][4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            a[i][j] = State[i][j];
        }
    }

    for (int i = 0; i < 4; i++)
    {
        State[0][i] = GMul(a[0][i], 2) ^ a[3][i] ^ a[2][i] ^ GMul(a[1][i], 3);
        State[1][i] = GMul(a[1][i], 2) ^ a[0][i] ^ a[3][i] ^ GMul(a[2][i], 3);
        State[2][i] = GMul(a[2][i], 2) ^ a[1][i] ^ a[0][i] ^ GMul(a[3][i], 3);
        State[3][i] = GMul(a[3][i], 2) ^ a[2][i] ^ a[1][i] ^ GMul(a[0][i], 3);
    }
    
    return;
}

void InvMixColumn(unsigned char State[4][4])
{
    unsigned char a[4][4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            a[i][j] = State[i][j];
        }
    }

    for (int i = 0; i < 4; i++)
    {
        State[0][i] = GMul(a[0][i], 0x0e) ^ GMul(a[3][i], 0x09) ^ GMul(a[2][i], 0x0d) ^ GMul(a[1][i], 0x0b);
        State[1][i] = GMul(a[1][i], 0x0e) ^ GMul(a[0][i], 0x09) ^ GMul(a[3][i], 0x0d) ^ GMul(a[2][i], 0x0b);
        State[2][i] = GMul(a[2][i], 0x0e) ^ GMul(a[1][i], 0x09) ^ GMul(a[0][i], 0x0d) ^ GMul(a[3][i], 0x0b);
        State[3][i] = GMul(a[3][i], 0x0e) ^ GMul(a[2][i], 0x09) ^ GMul(a[1][i], 0x0d) ^ GMul(a[0][i], 0x0b);
    }
    return;
}

void EncryptBlock(unsigned char In[16], unsigned char Key[16], unsigned char Out[16])
{
    unsigned char Block[4][4] =
    {
        {In[0], In[4], In[8], In[12]},
        {In[1], In[5], In[9], In[13]},
        {In[2], In[6], In[10], In[14]},
        {In[3], In[7], In[11], In[15]}
    };

    // Expands key to fill all rounds
    unsigned char KeySchedule[11][16];
    ExpandKey(Key, KeySchedule);

    //cout << "Starting State: " << endl;
    //PrintState(Block);

    AddRoundKey(Block, KeySchedule[0]);
    //cout << "First Add Key: " << endl;
    //PrintState(Block);

    for (int rounds = 1; rounds < 10; rounds++) // Does all rounds expect the last
    {
        SubByte(Block);
        ShiftRow(Block);
        MixColumn(Block);
        AddRoundKey(Block, KeySchedule[rounds]); // KeySchedule is broken, all the rest are verified.
        //cout << "Round: " << rounds << endl;
        //PrintState(Block);
    }

    // Last round, excludes MixColumns.
    SubByte(Block);
    ShiftRow(Block);
    AddRoundKey(Block, KeySchedule[10]);

    //PrintState(Block);
    int count = 0;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            Out[count] = Block[j][i];
            count++;
        }
    }
    return;
}

void DecryptBlock(unsigned char In[16], unsigned char Key[16], unsigned char Out[16])
{
    unsigned char Block[4][4] =
    {
        {In[0], In[4], In[8], In[12]},
        {In[1], In[5], In[9], In[13]},
        {In[2], In[6], In[10], In[14]},
        {In[3], In[7], In[11], In[15]}
    };

    // Expands key to fill all rounds
    unsigned char KeySchedule[11][16];
    ExpandKey(Key, KeySchedule);

    //cout << "Starting State: " << endl;
    //PrintState(Block);

    AddRoundKey(Block, KeySchedule[10]);
    //cout << "First Add Key: " << endl;
    //PrintState(Block);

    for (int rounds = 9; rounds > 0; rounds--) // Does all rounds except the last
    {
        InvShiftRow(Block);
        InvSubByte(Block);
        AddRoundKey(Block, KeySchedule[rounds]);
        InvMixColumn(Block);

        //cout << "Round: " << rounds << endl;
        //PrintState(Block);
    }

    // Last round, excludes MixColumns.
    InvShiftRow(Block);
    InvSubByte(Block);
    AddRoundKey(Block, KeySchedule[0]);

    //PrintState(Block);
    int count = 0;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            Out[count] = Block[j][i];
            count++;
        }
    }
    return;
}


// Debug Functions
void PrintState(unsigned char State[4][4])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            cout << "[0x" << setw(2) << setfill('0') << hex << (int) State[i][j] << "] ";
        }
        cout << endl;
    }
    cout << endl;
    return;
}

void PrintKey(unsigned char Key[16])
{
    unsigned char Temp[4][4];
    unsigned char count = 0;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            Temp[j][i] = Key[count];
            count++;
        }
        
    }

    for (int i = 0; i < 4; i++)
    {
        cout << endl;
        for (int j = 0; j < 4; j++)
        {
            cout << hex << "[0x" << setw(2) << setfill('0') << (int) Temp[i][j] << "] ";
        }
        
    }
    
    return;
}