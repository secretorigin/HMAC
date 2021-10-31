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
  // init ipad and opad
  uint8_t* ipad = new uint8_t[blockSize];
  uint8_t* opad = new uint8_t[blockSize];
  for (int i = 0; i < blockSize; i++) {
    ipad[i] = IPAD_NUMBER;
    opad[i] = OPAD_NUMBER;
  }

  // get expanded key
  uint8_t* k0 = new uint8_t[blockSize];
  if (ksize > blockSize) {
    uint8_t* hashedkey = HF(k, ksize);
    for (int i = 0 ; i < blockSize; i++)
      if (i < hashSize)
        k0[i] = hashedkey[i];
      else
        k0[i] = 0;
    delete[] hashedkey;
  } else if (ksize <= blockSize) {
    for (int i = 0 ; i < blockSize; i++)
      if (i < ksize)
        k0[i] = k[i];
      else
        k0[i] = 0;
  }

  // ipad and opad operations
  uint8_t* k0_ipad = new uint8_t[blockSize];
  uint8_t* k0_opad = new uint8_t[blockSize];
  for (int i = 0; i < blockSize; i++) {
    k0_ipad[i] = k0[i] ^ ipad[i];
    k0_opad[i] = k0[i] ^ opad[i];
  }
  delete[] k0;
  delete[] ipad;
  delete[] opad;

  // create first hashed data
  uint8_t* firsthashed = new uint8_t[blockSize + dsize];
  std::memcpy(firsthashed, k0_ipad, blockSize);
  std::memcpy(&(firsthashed[blockSize]), d, dsize);
  delete[] k0_ipad;

  // get first hash
  uint8_t* firsthash = HF(firsthashed, blockSize + dsize);
  delete[] firsthashed;

  // create last hashed data
  uint8_t* lasthashed = new uint8_t[blockSize + hashSize];
  std::memcpy(lasthashed, k0_opad, blockSize);
  delete[] k0_opad;
  std::memcpy(&(lasthashed[blockSize]), firsthash, hashSize);
  delete[] firsthash;

  uint8_t* hash = HF(lasthashed, blockSize + hashSize);
  delete[] lasthashed;

  // return last hash
  return hash;
}