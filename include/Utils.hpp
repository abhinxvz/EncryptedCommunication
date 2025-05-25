/**
 * @file Utils.hpp
 * @author abhinxvz
 * @brief This file contains utility functions common to all the modules in the project
 */

#pragma once

#include <string>
#include <vector>

/**
 * @brief Adds a specifed padding character to a string or truncates it if needed, depending on the numberOfBytes specified
 * @param str Original string
 * @param numberOfBytes The number of bytes that have to be reached
 * @param paddingChar The character used for padding
 * @returns A string of numberOfBytes bytes
 */
std::string padString(const std::string& str, size_t numberOfBytes,char paddingChar);

/**
 * @brief Generates a string of a specified number of bytes
 * @param length The desired length of the string
 * @returns A string of length bytes
 */
std::string generateRandomString(size_t length);

/**
 * @brief Writes a file
 * @param path Path of the file to be written
 * @param content Content of the file
 */
void writeFile(const std::string& path,const std::string& content);

/**
 * @brief Reads a file
 * @param path Path of the file to be read
 * @returns A string with the file content
 */
std::string readFile(const std::string& path);

/**
 * @brief Deletes a file
 * @param path Path of the file to be deleted
 */
void deleteFile(const std::string& path);

/**
 * @brief Encodes a string in base 64
 * @param payload Payload to be encoded
 * @returns A base 64 encoded string
 */
std::string encodeInBase64(const std::vector<unsigned char>& payload);

/**
 * @brief Decodes a string from base 64
 * @param payload Base 64 encoded string
 * @returns A base 64 decoded string
 */
std::vector<unsigned char> decodeFromBase64(const std::string& payload);