// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief sha256 function implementation
 */



#include <iomanip>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <limits.h>   // for CHAR_BIT

#include "sha256.h"



/**
 * @brief functions for rotate right (like right shift but with saving bits)
 * 
 * @param [in] n value we need to rotate
 * @param [in] c number of turns
 *
 * @return updated value
 *
 * source: https://stackoverflow.com/questions/776508/best-practices-for-circular-shift-rotate-operations-in-c
 */
static inline uint32_t rightrotate(uint32_t n, unsigned int c) {
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);
  // assert ( (c<=mask) &&"rotate by type width or more");
  c &= mask;
  return (n>>c) | (n<<( (-c)&mask ));
}



/**
 * @brief expands data (sha256)
 * 
 * @param [in] data data to be expanded
 * @param [in] size data size
 * @param [out] newSize size of expanded data
 *
 * @return updated data created using 'new' operator
 *
 * Add byte '10000000', add bytes so that the size is a multiple of 512, and set size of data 
 * in the end (8 bytes);
 */
static uint8_t* preprocessor(const uint8_t* data, uint64_t size, uint64_t& newSize) {
  newSize = size + 1 + SHA256_BLOCK_SIZE - ((size + 1) % SHA256_BLOCK_SIZE);
  uint8_t* newArray = new uint8_t[newSize];

  // set it to 10000000
  newArray[size] = SHA256_FIRST_ADDED_BYTE;
  // copy data
  std::memcpy(newArray, data, size * sizeof(uint8_t));
  // set bits to 0
  for (int i = size + 1; i < newSize; i++)
    newArray[i] = 0;

  // set size of array in the end
  uint64_t writedSize = size * 8;
  for (int i = 0; i < 4; i++)
    std::memcpy(&(newArray[newSize - 1 - i]), reinterpret_cast<uint8_t*>(&writedSize) + i, sizeof(uint8_t));

  return newArray;
}



/**
 * @brief copy with big-little endian conversion
 * 
 * @param [out] dest data to be saved
 * @param [in] src copyed data
 * @param [in] srcSize size of copyed data
 */
static void copyWithEndianConversion(uint32_t* dest, const uint8_t* src, uint64_t srcSize) {
  for (int i = 0; i < srcSize; i++)
      for (int j = 0; j < DIFF_32_8; j++)
        std::memcpy((reinterpret_cast<uint8_t*>(dest) + i * DIFF_32_8 + j),
                    &(src[i * DIFF_32_8 + (DIFF_32_8 - 1) - j]), sizeof(uint8_t));
}



/**
 * @brief copy with big-little endian conversion
 * 
 * @param [out] dest data to be saved
 * @param [in] src copyed data
 * @param [in] srcSize size of copyed data
 */
static void copyWithEndianConversion(uint8_t* dest, const uint32_t* src, uint64_t srcSize) {
  for (int i = 0; i < srcSize; i++)
    for (int j = 0; j < DIFF_32_8; j++)
      std::memcpy(&(dest[i * DIFF_32_8 + j]), reinterpret_cast<const int8_t*>(&src[i]) + (DIFF_32_8 - 1) - j, sizeof(uint32_t));
}



/**
 * @brief create sha256 hash
 * 
 * @param [in] data data to be hashed
 * @param [in] size data size
 *
 * @return hash
 *
 * Main function in sha256 algorithm
 */
uint8_t* sha256(const uint8_t* data, uint64_t size) {
  uint8_t* eData; ///< adding up to 512 bits
  uint64_t newSize; ///< size of exteded data, newSize % 512 = 0

  // set '1' and lots of '0' with size in the end
  eData = preprocessor(data, size, newSize);

  // get constants for process
  uint32_t h[SHA256_SQRT_NUM];
  for (int i = 0; i < SHA256_SQRT_NUM; i++)
    h[i] = h_[i];

  int numOfChunks = newSize / SHA256_BLOCK_SIZE;

  // chunk processor
  for (int y = 0; y < numOfChunks; y++) {
    uint32_t* eeData = new uint32_t[SHA256_BLOCK_SIZE]; ///< data extended one more time
    // copy chunk, very strange way because of big-endian order in sha256
    copyWithEndianConversion(eeData, &(eData[y * SHA256_BLOCK_SIZE]), SHA256_BLOCK_SIZE/DIFF_32_8);
    // extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
    for (int i = (SHA256_BLOCK_SIZE / DIFF_32_8); i < SHA256_BLOCK_SIZE; i++) {
      uint32_t s0 = rightrotate(eeData[i - 15], 7) ^ rightrotate(eeData[i - 15], 18) ^ (eeData[i - 15] >> 3);
      uint32_t s1 = rightrotate(eeData[i - 2], 17) ^ rightrotate(eeData[i - 2], 19) ^ (eeData[i - 2] >> 10);
      eeData[i] = eeData[i - 16] + s0 + eeData[i - 7] + s1;
    }

    // init a[] array
    uint32_t a[SHA256_SQRT_NUM];
    for (int i = 0; i < SHA256_SQRT_NUM; i++)
      a[i] = h[i];

    // compression function main loop
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
      uint32_t s1 = rightrotate(a[4], 6) ^ rightrotate(a[4], 11) ^ rightrotate(a[4], 25);
      uint32_t ch = (a[4] & a[5]) ^ ((~a[4]) & a[6]);
      uint32_t temp1 = a[7] + s1 + ch + k_[i] + eeData[i];

      uint32_t s0 = rightrotate(a[0], 2) ^ rightrotate(a[0], 13) ^ rightrotate(a[0], 22);
      uint32_t maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
      uint32_t temp2 = s0 + maj;

      // set a[] array
      a[7] = a[6];
      a[6] = a[5];
      a[5] = a[4];
      a[4] = a[3] + temp1;
      a[3] = a[2];
      a[2] = a[1];
      a[1] = a[0];
      a[0] = temp1 + temp2;
    }

    // add a[] array to h[] array
    for (int j = 0; j < SHA256_SQRT_NUM; j++)
      h[j] = h[j] + a[j];

    delete[] eeData;
  }
  
  delete[] eData;

  uint8_t* hash = new uint8_t[SHA256_HASH_SIZE];
  copyWithEndianConversion(hash, h, SHA256_SQRT_NUM);
  return hash;
}



/**
 * @brief create sha256 hash
 * 
 * @param [in] data data to be hashed
 * @param [in] size data size
 *
 * @return hash
 *
 * Used SHA256::get to get hash in std::string hex format
 */
std::string sha256_str(const uint8_t* data, uint64_t size) {
  uint8_t* hash = sha256(data, size);

  std::stringstream s;
	s << std::setfill('0') << std::hex;
	for(uint8_t i = 0 ; i < 32 ; i++)
		s << std::setw(2) << (unsigned int) hash[i];

  return s.str();
}