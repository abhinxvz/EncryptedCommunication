/**
 * @file AES256EncryptorHandler.cpp
 * @author abhinxvz
 * @brief Implementation file for AES256EncryptorHandler.hpp
 */

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <vector>

#include "AES256EncryptorHandler.hpp"
#include "Utils.hpp"

std::string AES256EncryptorHandler::generateKey()
{
    return generateRandomString(32);
}

std::string AES256EncryptorHandler::encrypt(const std::string& plaintext,const std::string& key)
{
    std::string normalizedKey = padString(key,32,'0');
    std::string initVector = generateRandomString(AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if(!context)
    {
        throw CryptoHandlerException("Failed to create EVP_CIPHER_CTX object");
    }

    const unsigned char* keyPtr = reinterpret_cast<const unsigned char*>(normalizedKey.data());
    const unsigned char* ivPtr = reinterpret_cast<const unsigned char*>(initVector.data());
    
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, keyPtr, ivPtr) != 1) 
    {
        EVP_CIPHER_CTX_free(context);
        throw CryptoHandlerException("Failed to create initialize symmetric encryption object");
    }

    std::vector<unsigned char> encrypted(plaintext.size() + AES_BLOCK_SIZE);
    int encryptedLen = 0;

    const unsigned char* plaintextPtr = reinterpret_cast<const unsigned char*>(plaintext.data());
    
    if (EVP_EncryptUpdate(context, encrypted.data(), &encryptedLen, plaintextPtr, plaintext.length()) != 1) 
    {
        EVP_CIPHER_CTX_free(context);
        throw CryptoHandlerException("Failed to update the encryption");
    }

    encrypted.resize(encryptedLen);
    EVP_CIPHER_CTX_free(context);
    
    return initVector + encodeInBase64(encrypted);
}

std::string AES256EncryptorHandler::decrypt(const std::string& base64EncodedCyphertext,const std::string& key)
{
    std::string normalizedKey = padString(key,32,'0');
    std::string extractedIV(AES_BLOCK_SIZE,'0');

    std::copy(base64EncodedCyphertext.begin(), base64EncodedCyphertext.begin() + AES_BLOCK_SIZE, extractedIV.begin());

    std::vector<unsigned char> encryptedData = decodeFromBase64(std::string(base64EncodedCyphertext.begin() + AES_BLOCK_SIZE,base64EncodedCyphertext.end()));

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if(!context)
    {
        throw CryptoHandlerException("Failed to create EVP_CIPHER_CTX object");
    }

    const unsigned char* keyPtr = reinterpret_cast<const unsigned char*>(normalizedKey.data());
    const unsigned char* ivPtr = reinterpret_cast<const unsigned char*>(extractedIV.data());
    
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, keyPtr, ivPtr) != 1) 
    {
        EVP_CIPHER_CTX_free(context);
        throw CryptoHandlerException("Failed to create initialize symmetric decryption object");
    }

    std::vector<unsigned char> decrypted(encryptedData.size());
    int decryptedLen = 0;

    if (EVP_DecryptUpdate(context, decrypted.data(), &decryptedLen, encryptedData.data(), encryptedData.size()) != 1) 
    {
        EVP_CIPHER_CTX_free(context);
        throw CryptoHandlerException("Failed to update the decryption object");
    }

    decrypted.resize(decryptedLen);
    EVP_CIPHER_CTX_free(context);

    return std::string(decrypted.begin(), decrypted.end());
}