/**
 * @file CryptoHandler.hpp
 * @author abhinxvz
 * @brief This file contains the definition of the classes CryptoHandler and CryptoHandlerException
 */

#pragma once

#include <exception>

#include <string>

/**
 * @class CryptoHandler
 * @brief Abstract class that define the interface of a module that encrypts and decrypts strings
 */
class CryptoHandler
{
    public:
        virtual std::string encrypt(const std::string& message,const std::string& key) = 0;
        virtual std::string decrypt(const std::string& message,const std::string& key) = 0;       
};

/**
 * @extends std::exception
 * @class CryptoHandlerException
 * @brief Custom exception that signals the errors in the library
 */
class CryptoHandlerException : public std::exception
{

    private : 
        
        /**
         * @brief message to be displayed
         */
        std::string message;

    public :
    
        /**
         * @brief constructor for the class CryptoHandlerException
         */
        CryptoHandlerException(const char* msg):message(msg)
        {}

        /**
         * @brief override of the what function
         */
        const char* what() const throw()
        {
            return message.c_str();
        }
};