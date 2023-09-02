#include <iostream>
#include <iomanip>
#include "AES.cpp"

using namespace std;

void PrintArr(uint8_t *arr);
void PrintBlock(uint8_t *arr);

int main()
{
    AES Aes;
    uint8_t plaintext[16] = 
    {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    uint8_t key[16] = 
    {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    cout << "Plaintext : ";
    PrintArr(plaintext);
    cout << "Key       : ";
    PrintArr(key);
    cout << endl;

    Aes.Encrypt(plaintext, key);
    cout << "Ciphertext: ";
    PrintArr(plaintext);
    cout << endl;

    Aes.Decrypt(plaintext, key);
    cout << "Decrypted : ";
    PrintArr(plaintext);
}

void PrintArr(uint8_t *arr)
{
    for(int i = 0; i < 16; i++)
    {
        cout << "0x" << setfill('0') << setw(2) << hex << (int) arr[i] << " ";
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