#include <random>
#include <stdexcept>

#include "AES256EncryptorHandler.hpp"
#include "Utils.hpp"

bool test_saveKeyToFileAndSaveCyphertextThenReadAndDecrypt()
{
    AES256EncryptorHandler test;

    const std::string key = test.generateKey();

    const std::string message = "This is a secret message! I hope no one is able to decrypt it";

    writeFile("sKey.txt",key);
    writeFile("cyphertext.txt",test.encrypt(message,key));

    const std::string rKey = readFile("sKey.txt"); 
    const std::string cyphertext = readFile("cyphertext.txt");

    deleteFile("sKey.txt");
    deleteFile("cyphertext.txt");

    return message == test.decrypt(cyphertext,rKey);
}

bool test_noInitVector()
{
    AES256EncryptorHandler test;

    std::string cypherText = test.encrypt("Hello","12345");

    bool result;

    try
    {
        test.decrypt("c","1234");
        result = false;
    }
    catch(const std::length_error& e)
    {
        result = true;
    }

    return result;
}

bool test_differentKey()
{
    AES256EncryptorHandler test;

    std::string cypherText = test.encrypt("Hello","12345");
    std::string plainText = test.decrypt(cypherText,"1234");

    return plainText != "Hello";
}

bool test_emptyString()
{
    AES256EncryptorHandler test;

    const std::string key = test.generateKey();

    const std::string message = "";
    bool result;
    try
    {
        test.encrypt(message,key);
        result = false;
    }
    catch(const std::length_error& e)
    {
        result = true;
    }

    return result;
}

bool test_edgeCases()
{
    if(!test_emptyString())
        return false;

    if(!test_differentKey())
        return false;

    if(!test_noInitVector())
        return false;

    return true;
}

bool test_stressTest_randomKeyRandomLengthMessage()
{
    /* Maximum 1 MB messages */
    const int maximumNumberOfBytesOfTheMessage = 1000000;
    const int numberOfIterations = 1000;

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(1,maximumNumberOfBytesOfTheMessage);

    AES256EncryptorHandler test;

    for(int i = 0 ; i < numberOfIterations; i++)
    {
        const std::string key = test.generateKey();

        const std::string message = generateRandomString(distribution(generator));

        const std::string cyphertext = test.encrypt(message,key);
    
        if(message != test.decrypt(cyphertext,key))
            return false;
    }

    return true;
}

bool test_stressTest_sameKeyRandomLengthMessage()
{
    /* Maximum 1 MB messages */
    const int maximumNumberOfBytesOfTheMessage = 1000000;
    const int numberOfIterations = 1000;

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(1,maximumNumberOfBytesOfTheMessage);

    AES256EncryptorHandler test;

    const std::string key = test.generateKey();


    for(int i = 0 ; i < numberOfIterations; i++)
    {
        const std::string message = generateRandomString(distribution(generator));

        const std::string cyphertext = test.encrypt(message,key);
    
        if(message != test.decrypt(cyphertext,key))
            return false;
    }

    return true;
}

bool test_randomMessages_2048Bit()
{
    AES256EncryptorHandler test;
    const std::string key = test.generateKey();
    const std::string message = generateRandomString(2048);
    const std::string cyphertext = test.encrypt(message,key);
    return message == test.decrypt(cyphertext,key);
}

bool test_helloWorld()
{
    AES256EncryptorHandler test;
    const std::string key = test.generateKey();
    const std::string message = "Hello world!";
    const std::string cyphertext = test.encrypt(message,key);
    return message == test.decrypt(cyphertext,key);
}

int main (int argc, char* argv[])
{
    if(!test_helloWorld())
        return -1;

    if(!test_randomMessages_2048Bit())
        return -1;

    if(!test_stressTest_sameKeyRandomLengthMessage())
        return -1;

    if(!test_stressTest_randomKeyRandomLengthMessage())
        return -1;

    if(!test_edgeCases())
        return -1;

    if(!test_saveKeyToFileAndSaveCyphertextThenReadAndDecrypt())
        return -1;
        
    return 0;
}