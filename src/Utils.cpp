/**
 * @file Utils.cpp
 * @author abhinxvz
 * @brief Implementation file for Utils.hpp
 */

#include <openssl/evp.h>

#include <random>
#include <fstream>
#include <filesystem>
#include <algorithm>

#include "Utils.hpp"

std::string trimString(const std::string &str) 
{
    std::string strCopy = str;
    strCopy.erase(std::remove(strCopy.begin(), strCopy.end(), '\n'), strCopy.cend());
    strCopy.erase(std::remove(strCopy.begin(), strCopy.end(), '\0'), strCopy.cend());
    return strCopy;
}

std::string trimPadding(const std::string &str) 
{
    std::string strCopy = str;
    strCopy.erase(std::remove(strCopy.begin(), strCopy.end(), '='), strCopy.cend());
    return strCopy;
}

std::string padString(const std::string& str, size_t numberOfBytes,char paddingChar)
{
    if(str.size() >= numberOfBytes)
    {
        return str.substr(0,numberOfBytes);
    }
    
    std::string padded = str;
    padded.append(numberOfBytes - str.size(), paddingChar);
    return padded;
}

std::string generateRandomString(size_t length) 
{
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, charset.size() - 1);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) 
    {
        result += charset[dist(gen)];
    }

    return result;
}

void writeFile(const std::string& path,const std::string& content)
{
    std::ofstream output(path);

    if(!output.is_open())
    {
        throw std::runtime_error("Error while opening the specified file");
    }

    output << content;
    output.close();
}

std::string readFile(const std::string& path)
{
    std::ifstream input(path);

    if(!input.is_open())
    {
        throw std::runtime_error("Error while opening the specified file");
    }

    std::string data;
    std::string currentLine; 

    while (std::getline(input, currentLine))
    {
        data += currentLine;
    }

    input.close();

    return data;
}

void deleteFile(const std::string& path)
{
    if(!std::filesystem::remove(path))
        throw std::runtime_error("Tried to delete a non existent file");
}

std::string encodeInBase64(const std::vector<unsigned char>& payload)
{
    EVP_ENCODE_CTX *context = EVP_ENCODE_CTX_new();
    if(!context)
    {
        throw std::runtime_error("Failed to create EVP_ENCODE_CTX_new object");
    }
    EVP_EncodeInit(context);

    int blockCount = 1 + ((payload.size()-1)/48);
    int lastBlockSize = payload.size() - ((blockCount-1)*48);
    std::vector<unsigned char> encoded(65 * blockCount + 1);

    int bytesWritten = 0;
    for(uint i = 0 ; i < blockCount; i++)
    {        
        int currentBlockSize = (i == blockCount - 1) ? lastBlockSize : 48;
        
        if(EVP_EncodeUpdate(context, encoded.data() + 65*i, &bytesWritten, payload.data() + 48*i, currentBlockSize) <= 0)
        {
            EVP_ENCODE_CTX_free(context);
            throw std::runtime_error("Error while encoding the payload");
        }

        if(bytesWritten == 0)
        {
            EVP_EncodeFinal(context, encoded.data() + 65*(blockCount-1), &bytesWritten);
        }
    }

    EVP_ENCODE_CTX_free(context);

    return trimString(std::string(encoded.begin(), encoded.end()));
}

std::vector<unsigned char> decodeFromBase64(const std::string& payload)
{
    EVP_ENCODE_CTX *context = EVP_ENCODE_CTX_new();
    if(!context)
    {
        throw std::runtime_error("Failed to create EVP_ENCODE_CTX_new object");
    }
    EVP_DecodeInit(context);

    int blockCount = 1 + ((payload.size()-1)/80);
    int lastBlockSize = payload.size() - ((blockCount-1)*80);
    std::vector<unsigned char> decoded(3*payload.size()/4);

    int bytesWritten = 0;
    int totalSize = 0;
    const unsigned char* payloadPtr = reinterpret_cast<const unsigned char*>(payload.data());
    
    for(uint i = 0 ; i < (blockCount-1); i++)
    {        
        if(EVP_DecodeUpdate(context, decoded.data()+ 60*i, &bytesWritten, payloadPtr+ 80*i, 80) == -1)
        {
            EVP_ENCODE_CTX_free(context);
            throw std::runtime_error("Error while decoding the payload");
        }
        totalSize += bytesWritten;
    }

    if(EVP_DecodeUpdate(context, decoded.data()+ 60*(blockCount-1), &bytesWritten, payloadPtr+ 80*(blockCount-1), lastBlockSize) == -1)
    {
        EVP_ENCODE_CTX_free(context);
        throw std::runtime_error("Error while decoding the payload");
    }
    totalSize += bytesWritten;

    if(EVP_DecodeFinal(context, decoded.data()+ 60*(blockCount-1), &bytesWritten) == -1)
    {
        EVP_ENCODE_CTX_free(context);
        throw std::runtime_error("Error while decoding the payload");
    }
    totalSize += bytesWritten;

    decoded.resize(totalSize);
    EVP_ENCODE_CTX_free(context);

    return decoded;
}