EncryptedCommunication Library

A C++ cryptographic library providing AES256 encryption, RSA encryption, and SHA256 hashing capabilities using OpenSSL.

Features

AES256 Encryption
  Symmetric encryption using AES 256 GCM mode
  Automatic key generation (256 bit)
  Random initialization vector generation
  Base64 encoded output

RSA Encryption
  Asymmetric encryption with configurable key sizes
  Key pair generation
  PKCS1 OAEP padding
  Digital signature creation and verification
  Base64 encoded output

SHA256 Hashing
  Cryptographic hashing using SHA256 algorithm
  Base64 encoded output

Requirements

CMake 3.16 or higher
OpenSSL library
C++17 compatible compiler
Doxygen (optional, for documentation generation)

Building

mkdir build
cd build
cmake ..
make

Testing

After building, run tests with:
ctest

Or run individual test executables:
./Test_AES256EncryptorHandler
./Test_RSAEncryptorHandler
./Test_SHA256HashHandler
./Test_Utils

Usage Examples

AES256 Encryption

AES256EncryptorHandler aes;
std::string key = aes.generateKey();
std::string encrypted = aes.encrypt("Hello World", key);
std::string decrypted = aes.decrypt(encrypted, key);

RSA Encryption

RSAEncryptorHandler rsa;
RsaKeyPair keys = rsa.generateKeyPair(2048);
std::string encrypted = rsa.encrypt("Hello World", keys.publicKey);
std::string decrypted = rsa.decrypt(encrypted, keys.privateKey);

SHA256 Hashing

SHA256HashHandler sha;
std::string hash = sha.hash("Hello World");

Digital Signatures

RSAEncryptorHandler rsa;
SHA256HashHandler sha;
RsaKeyPair keys = rsa.generateKeyPair(2048);

std::string message = "Important message";
std::string digest = sha.hash(message);
std::string signature = rsa.signMessageDigestSha256(digest, keys.privateKey);
bool verified = rsa.verifyMessageDigestSha256(digest, signature, keys.publicKey);

Library Structure

include/
  AES256EncryptorHandler.hpp
  RSAEncryptorHandler.hpp
  SHAHashHandler.hpp
  CryptoHandler.hpp
  HashHandler.hpp
  Utils.hpp

src/
  AES256EncryptorHandler.cpp
  RSAEncryptorHandler.cpp
  SHAHashHandler.cpp
  Utils.cpp

test/
  Test_AES256EncryptorHandler.cpp
  Test_RSAEncryptorHandler.cpp
  Test_SHA256HashHandler.cpp
  Test_Utils.cpp

Documentation

Generate documentation using Doxygen:
make doc_doxygen

Documentation will be generated in the build directory.

License

This project uses OpenSSL which is licensed under the Apache License 2.0.

Author

abhinxvz
