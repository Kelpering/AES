#include <iostream>
#include <iomanip>
#include <vector>
#include "Encrypt.h"

using namespace std;

void PrintArr(uint8_t *arr);
void PrintArr(vector<uint8_t> vector);

void PrintBlock(uint8_t *arr);
void PrintBlock(vector<uint8_t> vector);

int main()
{
    vector<uint8_t> plaintext = 
    {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
        0x23
    };

    uint8_t key[16] = 
    {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // //* Looks like it works, seems to pad data as expected.
    
    // uint8_t* ciphertext = Enc.ECBEncrypt(plaintext, 17, key);
    // for (int i = 0; i < (2*16); i+=16)
    // {
    //     PrintBlock(ciphertext+i);
    // }
    // uint8_t* decipher = Enc.ECBDecrypt(ciphertext, 32, key);
    // for (int i = 0; i < (2*16); i+=16)
    // {
    //     PrintBlock(decipher+i);
    // }

    Encrypt Enc;

    PrintArr(plaintext);
    Enc.ECBEncryptNew(&plaintext, key);

    PrintArr(plaintext);
    Enc.ECBDecryptNew(&plaintext, key);

    PrintArr(plaintext);

    //Enc.ECBDecryptNew(&plaintext, key);

}

void PrintArr(uint8_t *arr)
{
    for(int i = 0; i < 16; i++)
    {
        cout << "0x" << setfill('0') << setw(2) << hex << (int) arr[i] << " ";
    }
    cout << endl;
}
void PrintArr(vector<uint8_t> vector)
{
    for(size_t i = 0; i < vector.size(); i++)
    {
        cout << "0x" << setfill('0') << setw(2) << hex << (int) vector[i] << " ";
    }
    cout << endl;
}

void PrintBlock(uint8_t *arr)
{
    for (int i = 0; i < 16; i++)
    {
        if (i%4 == 0)
        {
            cout << endl;
        }
        cout << "0x" << setfill('0') << setw(2) << hex << (int) arr[i] << " ";
    }
    cout << endl;
}
void PrintBlock(vector<uint8_t> vector)
{
    for (size_t i = 0; i < vector.size(); i++)
    {
        if (i%4 == 0)
        {
            cout << endl;
        }
        cout << "0x" << setfill('0') << setw(2) << hex << (int) vector[i] << " ";
    }
    cout << endl;
}