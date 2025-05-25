/**
 * @file HashHandler.hpp
 * @author abhinxvz
 * @brief This file contains the definition of the classes HashHandler and HashHandlerException
 */

#pragma once

#include <exception>

#include <string>

/**
 * @class HashHandler
 * @brief Abstract class that define the interface of a module that hashes strings
 * 
 * This class handles the hash algorithms calls to openssl
 */
class HashHandler
{
    public :
        virtual std::string hash(const std::string& payload) = 0;
};

/**
 * @extends std::exception
 * @class HashHandlerException
 * @brief Custom exception that signals the errors in the library
 */
class HashHandlerException : public std::exception
{

    private : 
        
        /**
         * @brief message to be displayed
         */
        std::string message;

    public :
    
        /**
         * @brief constructor for the class HashHandlerException
         */
        HashHandlerException(const char* msg):message(msg)
        {}

        /**
         * @brief override of the what function
         */
        const char* what() const throw()
        {
            return message.c_str();
        }
};