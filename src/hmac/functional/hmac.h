// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief hmac function implemetation
 */



#ifndef HMAC_H
#define HMAC_H


// magic numbers
#define IPAD_NUMBER 0x36
#define OPAD_NUMBER 0x5c



// hashing algorithm
uint8_t* hmac(uint8_t* (*HF)(const uint8_t* data, uint64_t size), 
              uint16_t hashSize, uint16_t blockSize, 
              const uint8_t* d, uint64_t dsize, const uint8_t* k, uint64_t ksize);


#endif