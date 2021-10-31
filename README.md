<h1>HMAC</h1>

HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. As with any MAC, it may be used to simultaneously verify both the data integrity and the authenticity of a message.[wiki](https://en.wikipedia.org/wiki/HMAC)

Can be used with [SHA256](https://github.com/p2034/SHA256) (../SHA256)

<h2>Usage:</h2>

There is two versions of hmac: oop (class hmac) and functional (one function), copy one of them in your project.

<h2>Compile:</h2>

1. Go to tmp
2. Run:

```bash
cmake ./
make
```

3. And now you have test.out file in tmp
