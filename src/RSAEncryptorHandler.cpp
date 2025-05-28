/**
 * @file RSAEncryptorHandler.cpp
 * @author abhinxvz
 * @brief Implementation file for RSAEncryptorHandler.hpp
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

#include <vector>

#include "RSAEncryptorHandler.hpp"
#include "Utils.hpp"

EVP_PKEY* stringToEVP_PKEY(const std::string& stringKey,int keyType)
{
    const unsigned char* keyData = reinterpret_cast<const unsigned char*>(stringKey.data());
    size_t keyLength = stringKey.size();

    EVP_PKEY* resultKey = nullptr;

    OSSL_DECODER_CTX* decoderCtx = OSSL_DECODER_CTX_new_for_pkey(&resultKey, "PEM", nullptr, "RSA", keyType, nullptr, nullptr);
    if (!decoderCtx) 
    {
        throw CryptoHandlerException("Failed to create OSSL_DECODER_CTX");
    }

    if (OSSL_DECODER_from_data(decoderCtx, &keyData, &keyLength) <= 0) 
    {
        throw CryptoHandlerException("Failed to decode PEM key from data");
    }

    OSSL_DECODER_CTX_free(decoderCtx);

    return resultKey;
}

EVP_PKEY* privateKeyStringToEVP_PKEY(const std::string& privateKey)
{
    return stringToEVP_PKEY(privateKey,OSSL_KEYMGMT_SELECT_KEYPAIR);
}

EVP_PKEY* publicKeyStringToEVP_PKEY(const std::string& publicKey)
{
    return stringToEVP_PKEY(publicKey,OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
}

RsaKeyPair EVP_PKEYToKeypair(EVP_PKEY* keyPair)
{
    char *buffer = nullptr;
    size_t bufferSize = 0;
    FILE *memStream = nullptr;

    memStream = open_memstream(&buffer, &bufferSize);
    PEM_write_PUBKEY(memStream, keyPair);
    fflush(memStream);
    std::string publicKey = buffer;
    fclose(memStream);

    memStream = open_memstream(&buffer, &bufferSize);
    PEM_write_PrivateKey(memStream, keyPair, nullptr, nullptr, 0, nullptr, nullptr);
    fflush(memStream);
    std::string privateKey = buffer;
    fclose(memStream);

    return {publicKey, privateKey};
}

RsaKeyPair RSAEncryptorHandler::generateKeyPair(int bits)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if(!context)
    {
        throw CryptoHandlerException("Failed to create EVP_PKEY_CTX object");
    }

    if (EVP_PKEY_keygen_init(context) <= 0) 
    {
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to initialize the key object");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(context, bits) <= 0) 
    {
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to set key length");
    }

    EVP_PKEY *generatedKey = nullptr;

    if (EVP_PKEY_keygen(context, &generatedKey) <= 0) 
    {
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to generate the keypair");
    }

    RsaKeyPair keyPair = EVP_PKEYToKeypair(generatedKey);

    EVP_PKEY_free(generatedKey);
    EVP_PKEY_CTX_free(context);

    return keyPair;
}

std::string RSAEncryptorHandler::encrypt(const std::string& plaintext,const std::string& key)
{
    EVP_PKEY *pubKey = publicKeyStringToEVP_PKEY(key);

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(pubKey, nullptr);
    if(!context)
    {
        EVP_PKEY_free(pubKey);
        throw CryptoHandlerException("Failed to create EVP_PKEY_CTX object");
    }

    if (EVP_PKEY_encrypt_init(context) <= 0) 
    {
        EVP_PKEY_free(pubKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to initialize the encryption object");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0) 
    {
        EVP_PKEY_free(pubKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to set the RSA padding");
    }

    size_t encryptedSize = 0;
    const unsigned char* plaintextPtr = reinterpret_cast<const unsigned char*>(plaintext.data());

    if (EVP_PKEY_encrypt(context, nullptr, &encryptedSize, plaintextPtr, plaintext.length()) <= 0) 
    {
        EVP_PKEY_free(pubKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to determine the cyphertext length");
    }

    std::vector<unsigned char> encrypted(encryptedSize);

    if (EVP_PKEY_encrypt(context, encrypted.data(), &encryptedSize, plaintextPtr, plaintext.length()) <= 0) 
    {
        EVP_PKEY_free(pubKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to encrypt the plaintext");
    }

    EVP_PKEY_free(pubKey);
    EVP_PKEY_CTX_free(context);

    return encodeInBase64(encrypted);
}

std::string RSAEncryptorHandler::decrypt(const std::string& base64EncodedCyphertext,const std::string& key)
{
    EVP_PKEY *privKey = privateKeyStringToEVP_PKEY(key);

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(privKey, nullptr);
    if(!context)
    {
        EVP_PKEY_free(privKey);
        throw CryptoHandlerException("Failed to create EVP_PKEY_CTX object");
    }

    if (EVP_PKEY_decrypt_init(context) <= 0) 
    {
        EVP_PKEY_free(privKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to initialize the decryption object");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) <= 0) 
    {
        EVP_PKEY_free(privKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to set the RSA padding");
    }

    std::vector<unsigned char> encryptedData = decodeFromBase64(base64EncodedCyphertext);

    size_t decryptedSize = 0;
    if (EVP_PKEY_decrypt(context, nullptr, &decryptedSize, encryptedData.data(), encryptedData.size()) <= 0) 
    {
        EVP_PKEY_free(privKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to determine the plaintext length");
    }

    std::vector<unsigned char> decrypted(decryptedSize);

    if (EVP_PKEY_decrypt(context, decrypted.data(), &decryptedSize, encryptedData.data(), encryptedData.size()) <= 0) 
    {
        EVP_PKEY_free(privKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to decrypt the cyphertext");
    }

    decrypted.resize(decryptedSize);

    EVP_PKEY_free(privKey);
    EVP_PKEY_CTX_free(context);

    return std::string(decrypted.begin(), decrypted.end());
}

std::string RSAEncryptorHandler::signMessageDigestSha256(const std::string& payload,const std::string& privateKey)
{
    EVP_PKEY *signingKey = privateKeyStringToEVP_PKEY(privateKey);

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(signingKey, nullptr);
    if(!context)
    {
        EVP_PKEY_free(signingKey);
        throw CryptoHandlerException("Failed to create EVP_PKEY_CTX object");
    }

    if (EVP_PKEY_sign_init(context) <= 0) 
    {
        EVP_PKEY_free(signingKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to initialize the initialization object");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) <= 0) 
    {
        EVP_PKEY_free(signingKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to set the RSA padding");
    }

    std::vector<unsigned char> decodedPayload = decodeFromBase64(payload);

    size_t sigSize = 0;
    if (EVP_PKEY_sign(context, nullptr, &sigSize, decodedPayload.data(), decodedPayload.size()) <= 0)
    {
        EVP_PKEY_free(signingKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to determine the signature length");
    }

    std::vector<unsigned char> sig(sigSize);

    if (EVP_PKEY_sign(context, sig.data(), &sigSize, decodedPayload.data(), decodedPayload.size()) <= 0)
    {
        EVP_PKEY_free(signingKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to sign the payload");
    }

    EVP_PKEY_free(signingKey);
    EVP_PKEY_CTX_free(context);

    return std::string(sig.begin(), sig.end());
}

bool RSAEncryptorHandler::verifyMessageDigestSha256(const std::string& messageDigest,const std::string& digitalSignature,const std::string& publicKey)
{
    EVP_PKEY *verifyKey = publicKeyStringToEVP_PKEY(publicKey);

    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(verifyKey, nullptr);
    if(!context)
    {
        EVP_PKEY_free(verifyKey);
        throw CryptoHandlerException("Failed to create EVP_PKEY_CTX object");
    }

    if (EVP_PKEY_verify_init(context) <= 0) 
    {
        EVP_PKEY_free(verifyKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to initialize the initialization object");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) <= 0) 
    {
        EVP_PKEY_free(verifyKey);
        EVP_PKEY_CTX_free(context);
        throw CryptoHandlerException("Failed to set the RSA padding");
    }

    std::vector<unsigned char> decodedDigest = decodeFromBase64(messageDigest);
    const unsigned char* sigPtr = reinterpret_cast<const unsigned char*>(digitalSignature.data());

    int result = EVP_PKEY_verify(context, sigPtr, digitalSignature.size(), decodedDigest.data(), decodedDigest.size());

    EVP_PKEY_free(verifyKey);
    EVP_PKEY_CTX_free(context);

    return result == 1;
}