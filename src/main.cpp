#include <iostream>
#include "AES.cpp"
using namespace std;

void PrintArr(uint8_t arr[16]);

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

    PrintArr(plaintext);

    uint8_t* ciphertext = Aes.Encrypt(plaintext, key);

    PrintArr(ciphertext);
    delete[] ciphertext;

}

void PrintArr(uint8_t *arr)
{
    for (int i = 0; i < 16; i++)
    {
        if (i%4 == 0)
        {
            cout << endl;
        }
        cout << hex <<(int) arr[i] << " ";
        
    }
    cout << endl;
}