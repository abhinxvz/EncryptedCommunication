/**
 * @file SHAHashHandler.cpp
 * @author abhinxvz
 * @brief Implementation file for SHAHashHandler.hpp
 */

#include <openssl/evp.h>

#include <vector>

#include "SHAHashHandler.hpp"
#include "Utils.hpp"

std::string SHA256HashHandler::hash(const std::string& payload)
{
    EVP_MD *algorithm = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    if (!algorithm) 
    {
        throw HashHandlerException("Error fetching SHA256 hash algorithm");
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) 
    {
        EVP_MD_free(algorithm);
        throw HashHandlerException("Error creating MD Context");
    }

    if (EVP_DigestInit(context, algorithm) <= 0) 
    {
        EVP_MD_free(algorithm);
        EVP_MD_CTX_free(context);
        throw HashHandlerException("Error while initializing the digest context");
    }

    if (EVP_DigestUpdate(context, payload.data(), payload.size()) <= 0) 
    {
        EVP_MD_free(algorithm);
        EVP_MD_CTX_free(context);
        throw HashHandlerException("Error while updating the digest context");
    }
    
    std::vector<unsigned char> hashResult(EVP_MAX_MD_SIZE);
    uint hashSize = 0;

    if (EVP_DigestFinal_ex(context, hashResult.data(), &hashSize) <= 0) 
    {
        EVP_MD_free(algorithm);
        EVP_MD_CTX_free(context);
        throw HashHandlerException("Error while finalizing the digest context");
    }

    EVP_MD_free(algorithm);
    EVP_MD_CTX_free(context);

    hashResult.resize(hashSize);
    
    return encodeInBase64(hashResult);
}