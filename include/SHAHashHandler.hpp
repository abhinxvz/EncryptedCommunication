/**
 * @file SHAHashHandler.hpp
 * @author abhinxvz
 * @brief This file contains the different classes that implement the SHA variants
 */

#include "HashHandler.hpp"

/**
 * @implements HashHandler
 * @class SHA256HashHandler
 * @brief Implements HashHandler interface
 * 
 * This class handles hashing functions using SHA 256 algorithm
 */
class SHA256HashHandler : public HashHandler
{
    public :

        /**
         * @brief Hashes a payload using SHA 256 algorithm
         * @param payload The string to be hashed
         * @returns Hashed base64 encoded string
         */
        std::string hash(const std::string& payload) override;
};