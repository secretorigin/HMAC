#include <iostream>
#include <stdexcept>
#include <bitset>

#include "hmac.h"
#include "sha256.h"

int main() {
  try {
    HMAC* hmac = new HMAC(sha256, SHA256_HASH_SIZE, 32);

    uint64_t keySize = 32;
    uint8_t* key = new uint8_t[keySize];
    uint64_t dataSize = 1024;
    uint8_t* data = new uint8_t[dataSize];

    uint8_t* hash = hmac->get(data, dataSize, key, keySize);
    
    std::cout << std::hex;
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
      std::cout << (unsigned int)hash[i];
    std::cout << std::endl;

    delete[] data;
    delete[] key;
    delete[] hash;

    //delete hmac;

  } catch(const std::exception& excpt) {
    std::cout << excpt.what() << "\n";
  }

	return 0;
}