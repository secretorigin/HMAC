<h1>HMAC</h1>

HASH IS NOT VALID, i don't know why ((

<h2>ToDo:</h2>

1. add std::string version
2. debug ((

HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. As with any MAC, it may be used to simultaneously verify both the data integrity and the authenticity of a message.[wiki](https://en.wikipedia.org/wiki/HMAC)

Can be used with [SHA256](https://github.com/p2034/SHA256) (../SHA256)

<h2>Usage:</h2>

There is two versions of hmac: oop (class hmac) and functional (one function), copy one of them in your project.

Example with sha256 from my repo:

```cpp
uint8_t* hash = hmac(sha256, SHA256_HASH_SIZE, SHA256_BLOCK_SIZE, data, dataSize, key, keySize);
```
or
```cpp
HMAC hmac(sha256, SHA256_HASH_SIZE, SHA256_BLOCK_SIZE);
uint8_t* hash = hmac.get(data, dataSize, key, keySize);
```

<h2>Compile:</h2>

1. Go to tmp
2. Run:

```bash
cmake ./
make
```

3. And now you have test.out file in tmp
