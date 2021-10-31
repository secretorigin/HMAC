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

  // init ipad and opad
  this->ipad_ = new uint8_t[blockSize_];
  this->opad_ = new uint8_t[blockSize_];
  for (int i = 0; i < blockSize_; i++) {
    ipad_[i] = IPAD_NUMBER;
    opad_[i] = OPAD_NUMBER;
  }
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
  uint8_t* k0 = new uint8_t[blockSize_];
  if (ksize > blockSize_) {
    uint8_t* hashedkey = HF_(k, ksize);
    for (int i = 0 ; i < blockSize_; i++)
      if (i < hashSize_)
        k0[i] = hashedkey[i];
      else
        k0[i] = 0;
    delete[] hashedkey;
  } else if (ksize <= blockSize_) {
    for (int i = 0 ; i < blockSize_; i++)
      if (i < ksize)
        k0[i] = k[i];
      else
        k0[i] = 0;
  }

  // ipad and opad operations
  uint8_t* k0_ipad = new uint8_t[blockSize_];
  uint8_t* k0_opad = new uint8_t[blockSize_];
  for (int i = 0; i < blockSize_; i++) {
    k0_ipad[i] = k0[i] ^ ipad_[i];
    k0_opad[i] = k0[i] ^ opad_[i];
  }

  // create first hashed data
  uint8_t* firsthashed = new uint8_t[blockSize_ + dsize];
  std::memcpy(firsthashed, k0_ipad, blockSize_);
  std::memcpy(&(firsthashed[blockSize_]), d, dsize);

  // get first hash
  uint8_t* firsthash = HF_(firsthashed, blockSize_ + dsize);

  // create last hashed data
  uint8_t* lasthashed = new uint8_t[blockSize_ + hashSize_];
  std::memcpy(lasthashed, k0_opad, blockSize_);
  std::memcpy(&(lasthashed[blockSize_]), firsthash, hashSize_);

  uint8_t* hash = HF_(lasthashed, blockSize_ + hashSize_);

  delete[] k0;
  delete[] k0_ipad;
  delete[] k0_opad;

  delete[] firsthashed;
  delete[] firsthash;
  
  delete[] lasthashed;

  // return last hash
  return hash;
}


/**
 * @brief delete opad and ipad
 */
HMAC::~HMAC() {
  delete[] this->ipad_;
  delete[] this->opad_;
}