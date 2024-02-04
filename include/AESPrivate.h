#pragma once
#include <stdint.h>
#include <stdlib.h>

#define ROTL8(x, shift) ((x<<shift) | (x >> (8 - shift)))

static uint8_t SBox[256];
static uint8_t InvSBox[256];
static void ShiftRows(uint8_t* State);
static void InvShiftRows(uint8_t* State);
static void SubBytes(uint8_t* State);
static void RotWord(uint8_t* Word);
static void SubWord(uint8_t* Word);
static void AddRoundKey(uint8_t* State, const uint8_t* EKey);
static void MixColumns(uint8_t* State);
static uint8_t GMul(uint8_t x, uint8_t y);
static uint8_t GInv(uint8_t a);
static uint32_t* KeyExpansion256(uint8_t* Key);
static uint8_t SBoxFunc(uint8_t B);
static uint8_t InvSBoxFunc(uint8_t B);
static void InvMixColumns(uint8_t* State);
static void InvSubBytes(uint8_t* State);

