// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief hmac oop implemetation
 */



#include <cstring>
#include <cstdint>

#include "hmac.h"



/**
 * @brief constructor, init
 * 
 * @param [in] HF hash function
 * @param [in] hashSize size of hash returned by HF
 * @param [in] blockSize size of block
 *
 * Just init HMAC with this parameters.
 */
HMAC::HMAC(uint8_t* (*HF)(const uint8_t* data, uint64_t size), uint16_t hashSize, uint16_t blockSize) {
  HF_ = HF;
  blockSize_ = blockSize;
}



/**
 * @brief get hash with key
 * 
 * @param [in] d data
 * @param [in] dsize data size
 * @param [in] k key
 * @param [in] ksize key size
 *
 * @return hash
 *
 * Produce hash using hash function and hmac algorithm.
 */
uint8_t* HMAC::get(const uint8_t* d, uint64_t dsize, const uint8_t* k, uint64_t ksize) const {
  // get expanded key
  uint8_t k0[blockSize_];
  std::memset(k0, 0, blockSize_);
  if (ksize > blockSize_) {
    uint8_t* khash = HF_(k, ksize);
    uint64_t size = (hashSize_ > blockSize_) ? hashSize_ : blockSize_;
    std::memcpy(k0, khash, size);
    delete[] khash;
  } else {
    std::memcpy(k0, k, ksize);
  }

  // ipad and opad operations
  uint8_t k0_ipad[blockSize_];
  uint8_t k0_opad[blockSize_];
  std::memset(k0_ipad, HMAC_IPAD_NUMBER, blockSize_);
  std::memset(k0_opad, HMAC_OPAD_NUMBER, blockSize_);
  for (int i = 0; i < blockSize_; i++) {
    k0_ipad[i] ^= k0[i];
    k0_opad[i] ^= k0[i];
  }

  // create first hashed data
  uint8_t firsthashed[blockSize_ + dsize];
  std::memcpy(firsthashed, k0_ipad, blockSize_);
  std::memcpy(firsthashed + blockSize_, d, dsize);

  // get first hash
  uint8_t* firsthash = HF_(firsthashed, blockSize_ + dsize);

  // create last hashed data
  uint8_t lasthashed[blockSize_ + hashSize_];
  std::memcpy(lasthashed, k0_opad, blockSize_);
  std::memcpy(lasthashed + blockSize_, firsthash, hashSize_);

  delete[] firsthash;

  uint8_t* hash = HF_(lasthashed, blockSize_ + hashSize_);

  // return last hash
  return hash;
}