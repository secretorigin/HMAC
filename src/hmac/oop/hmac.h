// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief hmac oop implemetation
 */



#ifndef HMAC_H
#define HMAC_H


// magic numbers
#define HMAC_IPAD_NUMBER 0x36
#define HMAC_OPAD_NUMBER 0x5c



/**
 * @class HMAC
 * @brief hashing algorithm
 */
class HMAC {
public:
  // set hash function and other parameters
  HMAC(uint8_t* (*HF)(const uint8_t* data, uint64_t size), uint16_t hashSize, uint16_t blockSize);

  // get hash
  uint8_t* get(const uint8_t* d, uint64_t dsize, const uint8_t* k, uint64_t ksize) const;

private:
  uint8_t* (*HF_)(const uint8_t* data, uint64_t size); ///< hash function
  uint16_t hashSize_; ///< size of hash returned by HF
  uint16_t blockSize_; ///< size of block
};



#endif