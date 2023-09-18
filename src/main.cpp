#include <iostream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <filesystem>
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
    //? All modes use vectors, Encrypt can convert base64 strings to vectors.
    //? Should allow for file readings.
    //! This works

    string path = "./test.txt";

    ifstream File(path, ios::binary);
    vector<uint8_t> buffer(istreambuf_iterator<char>(File), {});
    File.close();

    remove("test.txt.AES");
    ofstream FileWrite(path + ".AES", ios::out | ios::binary | ios::app);
    FileWrite.write((char *) &buffer[0], buffer.size());
    FileWrite.close();

    //* vector<uint8_t> plaintext;
    //* CinVector(&plaintext);
    
    //* Encrypt Enc;
    //* vector<uint8_t> Key = Enc.RandomKey();
    //* cout << "Key (Array): "; PrintArr(Key);
    //* cout << "Key (Base64): " << Enc.Base64Encode(&Key[0], Key.size()) << endl << endl;

    //* Enc.ECBEncrypt(&plaintext, &Key[0]);
    //* cout << "ciphertext (Array): "; PrintArr(plaintext);
    //* cout << "ciphertext (Base64): " << Enc.Base64Encode(&plaintext[0], plaintext.size()) << endl;

    //* Enc.ECBDecrypt(&plaintext, &Key[0]);
    //* PrintString(plaintext);


    //* Encrypt Enc;

    //* string Ciphertext64;
    //* cout << "Ciphertext (Base64): ";
    //* cin >> Ciphertext64;

    //* string Key64;
    //* cout << "Key (Base64): ";
    //* cin >> Key64;

    //* vector<uint8_t> Ciphertext = Enc.Base64Decode(Ciphertext64);
    //* vector<uint8_t> Key = Enc.Base64Decode(Key64);
    //* Enc.ECBDecrypt(&Ciphertext, &Key[0]);
    //* string test = Enc.VectorString(Ciphertext);
    //* cout << test << endl;

    //! File test, encrypt file time.
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