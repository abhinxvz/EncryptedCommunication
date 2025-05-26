/**
 * @file RSAEncryptorHandler.hpp
 * @author abhinxvz
 * @brief This file contains the class RSAEncryptorHandler
 */

#include "CryptoHandler.hpp"

/**
 * @struct RsaKeyPair
 * @brief Contains the public and private key
 */
struct RsaKeyPair
{
    /**
     * @brief Public key
     */
    std::string publicKey;
    
    /**
     * @brief Private key
     */
    std::string privateKey;
};

/**
 * @implements CryptoHandler
 * @class RSAEncryptorHandler
 * @brief Implements CryptoHandler interface
 * 
 * This class handles the generation of a random key pair, the encryption and decryption of strings using RSA asymmetric encryption
 */
class RSAEncryptorHandler : public CryptoHandler
{
    public :

        /**
         * @brief Generates a key pair
         * @param bits Number of bits of the key pair to be generated
         * @returns Keypair
         */
        RsaKeyPair generateKeyPair(int bits);

        /**
         * @brief Encrypts a message using RSA
         * @param plaintext Message to be encrypted
         * @param key Key to be used for RSA asymmetric encryption
         * @returns Encrypted cyphertext encoded in base 64
         */
        std::string encrypt(const std::string& plaintext,const std::string& key) override;

        /**
         * @brief Decrypts a message using RSA
         * @param base64EncodedCyphertext Base 64 encoded payload to be decrypted. The payload to be decrypted
         * @param key Key to be used for RSA asymmetric decryption
         * @returns Decrypted string
         */
        std::string decrypt(const std::string& base64EncodedCyphertext,const std::string& key) override;

        /**
         * @brief Signs a payload using a private key
         * @param payload The payload to be signed
         * @param privateKey Private key to be used for signing
         * @returns Signature of the payload
         */
        std::string signMessageDigestSha256(const std::string& payload,const std::string& privateKey);

        /**
         * @brief Verifies a digital signature of a mesagge digest
         * @param digitalSignature The digital signature to be verified
         * @param publicKey Public key used to verify the digital signature
         * @returns True if the digital signature is verified by the public key passed
         */
        bool verifyMessageDigestSha256(const std::string& messageDigest,const std::string& digitalSignature,const std::string& publicKey);
};