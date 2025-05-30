#include "SHAHashHandler.hpp"
#include "Utils.hpp"

/* 
    This test aims to verify that when executing a large
    amount of hashes, the hash function doesn't lunch an execption
*/
bool test_StressTest()
{
    SHA256HashHandler test;
    uint numberofIterations = 100000;

    uint lengthOfRandomString = 10000;

    for(uint i = 0 ; i < numberofIterations ; i++)
    {
        std::string randomString = generateRandomString(1000);
        test.hash(randomString);
    }

    return true;
}

bool test_KnownConversions()
{
    SHA256HashHandler test;

    std::string strs[]={
        "asdadasdfasdfcasdfASDGVFgsawerGFdASDaSDA;SIKCHJzo:iFDH BASWEO;8y urb;qoiyurbv;iohlki;fseh;slkdfh;aslIHF;OIursdfsdfs",
        "fvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkj",
        "fvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkj",
        "aslidjaksljfhdlksjdfnlksdvjnlkdjxvnlkxfdjvn",
        "094782598035479834750932485-9034285039485 f dkhjgfdk ugh 3497v7ng03583049809v5",
        "094782598035479834750932485-9034285039485 f dkhjgfdk ugh 3497v7ng03583049809v5-_+++0=-09-08998yufdusnbdavfclkjsdn/./?.s.qa'wepdoq3[0"
    };

    std::string hashedStrings[]={
        "eEJ6WC/rtMh5SQ+qMXlK8yBrBVzUzepki05daKl9kH4=",
        "RLNTs96Q8dK1dy83EkOhPJUqwEuqw7mYuW5bkSyPdPE=",
        "VS0MAAk+pz2jJ7IiW9uj617r8IBDD4cPXCZPpVp3UfY=",
        "pDklEWZl4YnJh5wmBkL3Fz6h2HnPOOz0sF4n84qyt2k=",
        "BliawGRn6motjc5mDdG6SCrvoCUTM0xtxU2g9ymL/M0=",
        "7l8kKw1KoDP6b6v6CxhXygRtZ1n+avYpxm1FowM+yRk="
    };

    for(uint i = 0 ; i < 6 ; i++)
    {
        if(test.hash(strs[i]) != hashedStrings[i])
            return false;
    }

    return true;
}

bool test_helloWorld()
{
    SHA256HashHandler test;
    const std::string message = "Hello world!";
    return "wFNeS+K3n/2TKRMFQ2v4iTFOSj+uwF7P/Lt98xrZ5Ro=" == test.hash(message);
}

int main (int argc, char* argv[])
{
    if(!test_helloWorld())
        return -1;

    if(!test_KnownConversions())
        return -1;

    if(!test_StressTest())
        return -1;

    return 0;
}