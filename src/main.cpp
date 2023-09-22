#include <iostream>
#include <iomanip>
#include <vector>
#include "Encrypt.h"

using namespace std;

void CinVector(vector<uint8_t>* vector);

void PrintArr(uint8_t *arr);
void PrintArr(vector<uint8_t> vector);

void PrintString(vector<uint8_t> vector);

void PrintBlock(uint8_t *arr);
void PrintBlock(vector<uint8_t> vector);

int main()
{
    string path;
    cout << "Path: ";
    cin >> path;

    Encrypt Enc;

    vector<uint8_t> key = Enc.RandomKey();

    Enc.FileEncryptECB(path, &key[0]);
    remove(&path[0]);
    Enc.FileDecryptECB(path + ".AES", &key[0]);

    return 0;
}

void CinVector(vector<uint8_t>* vector)
{
    string input;
    cout << "Enter Text: ";
    getline(cin, input);
    for (size_t i = 0; i < input.length(); i++)
        vector->push_back(input[i]);
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

void PrintString(vector<uint8_t> vector)
{
    cout << '\"';
    for(size_t i = 0; i < vector.size(); i++)
    {
        cout << (char) vector[i];
    }
    cout << '\"' << endl;
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
