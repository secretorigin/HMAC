// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief hmac function implemetation
 */



#include <cstring>
#include <cstdint>

#include "hmac.h"



/**
 * @brief get hash with key
 * 
 * @param [in] HF hash function
 * @param [in] hashSize size of hash returned by HF
 * @param [in] blockSize size of block
 * @param [in] d data
 * @param [in] dsize data size
 * @param [in] k key
 * @param [in] ksize key size
 *
 * @return hash
 *
 * Produce hash using hash function and hmac algorithm.
 */
uint8_t* hmac(uint8_t* (*HF)(const uint8_t* data, uint64_t size),
              uint16_t hashSize, uint16_t blockSize,
              const uint8_t* d, uint64_t dsize, const uint8_t* k, uint64_t ksize) {
  // get expanded key
  uint8_t k0[blockSize];
  std::memset(k0, 0, blockSize);
  if (ksize > blockSize) {
    uint8_t* khash = HF(k, ksize);
    uint64_t size = (hashSize < blockSize) ? hashSize : blockSize;
    std::memcpy(k0, khash, size);
    delete[] khash;
  } else {
    std::memcpy(k0, k, ksize);
  }

  // ipad and opad operations
  uint8_t k0_ipad[blockSize];
  uint8_t k0_opad[blockSize];
  std::memset(k0_ipad, HMAC_IPAD_NUMBER, blockSize);
  std::memset(k0_opad, HMAC_OPAD_NUMBER, blockSize);
  for (int i = 0; i < blockSize; i++) {
    k0_ipad[i] ^= k0[i];
    k0_opad[i] ^= k0[i];
  }

  // create first hashed data
  uint8_t firsthashed[blockSize + dsize];
  std::memcpy(firsthashed, k0_ipad, blockSize);
  std::memcpy(firsthashed + blockSize, d, dsize);

  // get first hash
  uint8_t* firsthash = HF(firsthashed, blockSize + dsize);

  // create last hashed data
  uint8_t lasthashed[blockSize + hashSize];
  std::memcpy(lasthashed, k0_opad, blockSize);
  std::memcpy(lasthashed + blockSize, firsthash, hashSize);
  
  delete[] firsthash;

  uint8_t* hash = HF(lasthashed, blockSize + hashSize);

  // return last hash
  return hash;
}