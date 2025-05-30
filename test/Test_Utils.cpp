#include <random>

#include "Utils.hpp"

bool test_randomLengthBase64Encoding()
{
    const int maxStrLen = 10000;

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(1,maxStrLen);

    const int strLen = distribution(generator);
    
    for(uint i = 0 ; i < 10000 ; i++)
    {
        std::string randomString  = generateRandomString(strLen);
        std::string encodedString = encodeInBase64(std::vector<unsigned char>(randomString.begin(),randomString.end()));
        std::vector<unsigned char> decodedStr = decodeFromBase64(encodedString);
        std::string decodedString(decodedStr.begin(),decodedStr.end());
        if(randomString != decodedString)
        {
            return false;
        }
    }

    return true;
}

bool test_KnownConversions()
{
    std::string strs[]={
        "asdadasdfasdfcasdfASDGVFgsawerGFdASDaSDA;SIKCHJzo:iFDH BASWEO;8y urb;qoiyurbv;iohlki;fseh;slkdfh;aslIHF;OIursdfsdfs",
        "fvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkj",
        "fvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkjfvslkjvlkcfxnlkjcxfdvnfdlkjvndlkfjnvdlkfjgndlkfjgnsdloivnzoilxnvklixngvdlosynrjgflsijfnlasdkvhnlkausdhfgl;kasuhf;lkasuifherli;kuwehrfliuwekrfhlasdkruhflkasunvf.kufasdnbgvlkausdghflakjfsgi;oasudhg;WOSIGJH';SIhdgad;flivjnas;ligjs;OILGH'WOSIEHG'wSOIJFGL;SDKFJ;SLKDJF'SPOIfudjg'pwSUIEOJTFG'PWSIEOJF'pSOEJF'PAEFSOJ'SFEOJ'SPOFJ';sODFJLSDKFJLKDSJFLDKSFJLDKFJGKJFDGHKFJGHKFJGHKJlksjflkdfjslkdfjsldkfjslkdjflksdfjlskdfjkjbvsiuwegbnweuiohwoeijpasjcnmworj3q2wruqp9fow8eury8923646342547623tdikuasyda7ifyhauiskhfalkj",
        "aslidjaksljfhdlksjdfnlksdvjnlkdjxvnlkxfdjvn",
        "094782598035479834750932485-9034285039485 f dkhjgfdk ugh 3497v7ng03583049809v5",
        "094782598035479834750932485-9034285039485 f dkhjgfdk ugh 3497v7ng03583049809v5-_+++0=-09-08998yufdusnbdavfclkjsdn/./?.s.qa'wepdoq3[0"
    };

    std::string strsEncoded[]={
        "YXNkYWRhc2RmYXNkZmNhc2RmQVNER1ZGZ3Nhd2VyR0ZkQVNEYVNEQTtTSUtDSEp6bzppRkRIIEJBU1dFTzs4eSB1cmI7cW9peXVyYnY7aW9obGtpO2ZzZWg7c2xrZGZoO2FzbElIRjtPSXVyc2Rmc2Rmcw==",
        "ZnZzbGtqdmxrY2Z4bmxramN4ZmR2bmZkbGtqdm5kbGtmam52ZGxrZmpnbmRsa2ZqZ25zZGxvaXZuem9pbHhudmtsaXhuZ3ZkbG9zeW5yamdmbHNpamZubGFzZGt2aG5sa2F1c2RoZmdsO2thc3VoZjtsa2FzdWlmaGVybGk7a3V3ZWhyZmxpdXdla3JmaGxhc2RrcnVoZmxrYXN1bnZmLmt1ZmFzZG5iZ3Zsa2F1c2RnaGZsYWtqZnNnaTtvYXN1ZGhnO1dPU0lHSkgnO1NJaGRnYWQ7ZmxpdmpuYXM7bGlnanM7T0lMR0gnV09TSUVIRyd3U09JSkZHTDtTREtGSjtTTEtESkYnU1BPSWZ1ZGpnJ3B3U1VJRU9KVEZHJ1BXU0lFT0pGJ3BTT0VKRidQQUVGU09KJ1NGRU9KJ1NQT0ZKJztzT0RGSkxTREtGSkxLRFNKRkxES1NGSkxES0ZKR0tKRkRHSEtGSkdIS0ZKR0hLSmxrc2pmbGtkZmpzbGtkZmpzbGRrZmpzbGtkamZsa3NkZmpsc2tkZmpramJ2c2l1d2VnYm53ZXVpb2h3b2VpanBhc2pjbm13b3JqM3Eyd3J1cXA5Zm93OGV1cnk4OTIzNjQ2MzQyNTQ3NjIzdGRpa3Vhc3lkYTdpZnloYXVpc2toZmFsa2o=",
        "ZnZzbGtqdmxrY2Z4bmxramN4ZmR2bmZkbGtqdm5kbGtmam52ZGxrZmpnbmRsa2ZqZ25zZGxvaXZuem9pbHhudmtsaXhuZ3ZkbG9zeW5yamdmbHNpamZubGFzZGt2aG5sa2F1c2RoZmdsO2thc3VoZjtsa2FzdWlmaGVybGk7a3V3ZWhyZmxpdXdla3JmaGxhc2RrcnVoZmxrYXN1bnZmLmt1ZmFzZG5iZ3Zsa2F1c2RnaGZsYWtqZnNnaTtvYXN1ZGhnO1dPU0lHSkgnO1NJaGRnYWQ7ZmxpdmpuYXM7bGlnanM7T0lMR0gnV09TSUVIRyd3U09JSkZHTDtTREtGSjtTTEtESkYnU1BPSWZ1ZGpnJ3B3U1VJRU9KVEZHJ1BXU0lFT0pGJ3BTT0VKRidQQUVGU09KJ1NGRU9KJ1NQT0ZKJztzT0RGSkxTREtGSkxLRFNKRkxES1NGSkxES0ZKR0tKRkRHSEtGSkdIS0ZKR0hLSmxrc2pmbGtkZmpzbGtkZmpzbGRrZmpzbGtkamZsa3NkZmpsc2tkZmpramJ2c2l1d2VnYm53ZXVpb2h3b2VpanBhc2pjbm13b3JqM3Eyd3J1cXA5Zm93OGV1cnk4OTIzNjQ2MzQyNTQ3NjIzdGRpa3Vhc3lkYTdpZnloYXVpc2toZmFsa2pmdnNsa2p2bGtjZnhubGtqY3hmZHZuZmRsa2p2bmRsa2ZqbnZkbGtmamduZGxrZmpnbnNkbG9pdm56b2lseG52a2xpeG5ndmRsb3N5bnJqZ2Zsc2lqZm5sYXNka3ZobmxrYXVzZGhmZ2w7a2FzdWhmO2xrYXN1aWZoZXJsaTtrdXdlaHJmbGl1d2VrcmZobGFzZGtydWhmbGthc3VudmYua3VmYXNkbmJndmxrYXVzZGdoZmxha2pmc2dpO29hc3VkaGc7V09TSUdKSCc7U0loZGdhZDtmbGl2am5hcztsaWdqcztPSUxHSCdXT1NJRUhHJ3dTT0lKRkdMO1NES0ZKO1NMS0RKRidTUE9JZnVkamcncHdTVUlFT0pURkcnUFdTSUVPSkYncFNPRUpGJ1BBRUZTT0onU0ZFT0onU1BPRkonO3NPREZKTFNES0ZKTEtEU0pGTERLU0ZKTERLRkpHS0pGREdIS0ZKR0hLRkpHSEtKbGtzamZsa2RmanNsa2RmanNsZGtmanNsa2RqZmxrc2Rmamxza2RmamtqYnZzaXV3ZWdibndldWlvaHdvZWlqcGFzamNubXdvcmozcTJ3cnVxcDlmb3c4ZXVyeTg5MjM2NDYzNDI1NDc2MjN0ZGlrdWFzeWRhN2lmeWhhdWlza2hmYWxramZ2c2xranZsa2NmeG5sa2pjeGZkdm5mZGxranZuZGxrZmpudmRsa2ZqZ25kbGtmamduc2Rsb2l2bnpvaWx4bnZrbGl4bmd2ZGxvc3lucmpnZmxzaWpmbmxhc2RrdmhubGthdXNkaGZnbDtrYXN1aGY7bGthc3VpZmhlcmxpO2t1d2VocmZsaXV3ZWtyZmhsYXNka3J1aGZsa2FzdW52Zi5rdWZhc2RuYmd2bGthdXNkZ2hmbGFramZzZ2k7b2FzdWRoZztXT1NJR0pIJztTSWhkZ2FkO2ZsaXZqbmFzO2xpZ2pzO09JTEdIJ1dPU0lFSEcnd1NPSUpGR0w7U0RLRko7U0xLREpGJ1NQT0lmdWRqZydwd1NVSUVPSlRGRydQV1NJRU9KRidwU09FSkYnUEFFRlNPSidTRkVPSidTUE9GSic7c09ERkpMU0RLRkpMS0RTSkZMREtTRkpMREtGSkdLSkZER0hLRkpHSEtGSkdIS0psa3NqZmxrZGZqc2xrZGZqc2xka2Zqc2xrZGpmbGtzZGZqbHNrZGZqa2pidnNpdXdlZ2Jud2V1aW9od29laWpwYXNqY25td29yajNxMndydXFwOWZvdzhldXJ5ODkyMzY0NjM0MjU0NzYyM3RkaWt1YXN5ZGE3aWZ5aGF1aXNraGZhbGtqZnZzbGtqdmxrY2Z4bmxramN4ZmR2bmZkbGtqdm5kbGtmam52ZGxrZmpnbmRsa2ZqZ25zZGxvaXZuem9pbHhudmtsaXhuZ3ZkbG9zeW5yamdmbHNpamZubGFzZGt2aG5sa2F1c2RoZmdsO2thc3VoZjtsa2FzdWlmaGVybGk7a3V3ZWhyZmxpdXdla3JmaGxhc2RrcnVoZmxrYXN1bnZmLmt1ZmFzZG5iZ3Zsa2F1c2RnaGZsYWtqZnNnaTtvYXN1ZGhnO1dPU0lHSkgnO1NJaGRnYWQ7ZmxpdmpuYXM7bGlnanM7T0lMR0gnV09TSUVIRyd3U09JSkZHTDtTREtGSjtTTEtESkYnU1BPSWZ1ZGpnJ3B3U1VJRU9KVEZHJ1BXU0lFT0pGJ3BTT0VKRidQQUVGU09KJ1NGRU9KJ1NQT0ZKJztzT0RGSkxTREtGSkxLRFNKRkxES1NGSkxES0ZKR0tKRkRHSEtGSkdIS0ZKR0hLSmxrc2pmbGtkZmpzbGtkZmpzbGRrZmpzbGtkamZsa3NkZmpsc2tkZmpramJ2c2l1d2VnYm53ZXVpb2h3b2VpanBhc2pjbm13b3JqM3Eyd3J1cXA5Zm93OGV1cnk4OTIzNjQ2MzQyNTQ3NjIzdGRpa3Vhc3lkYTdpZnloYXVpc2toZmFsa2pmdnNsa2p2bGtjZnhubGtqY3hmZHZuZmRsa2p2bmRsa2ZqbnZkbGtmamduZGxrZmpnbnNkbG9pdm56b2lseG52a2xpeG5ndmRsb3N5bnJqZ2Zsc2lqZm5sYXNka3ZobmxrYXVzZGhmZ2w7a2FzdWhmO2xrYXN1aWZoZXJsaTtrdXdlaHJmbGl1d2VrcmZobGFzZGtydWhmbGthc3VudmYua3VmYXNkbmJndmxrYXVzZGdoZmxha2pmc2dpO29hc3VkaGc7V09TSUdKSCc7U0loZGdhZDtmbGl2am5hcztsaWdqcztPSUxHSCdXT1NJRUhHJ3dTT0lKRkdMO1NES0ZKO1NMS0RKRidTUE9JZnVkamcncHdTVUlFT0pURkcnUFdTSUVPSkYncFNPRUpGJ1BBRUZTT0onU0ZFT0onU1BPRkonO3NPREZKTFNES0ZKTEtEU0pGTERLU0ZKTERLRkpHS0pGREdIS0ZKR0hLRkpHSEtKbGtzamZsa2RmanNsa2RmanNsZGtmanNsa2RqZmxrc2Rmamxza2RmamtqYnZzaXV3ZWdibndldWlvaHdvZWlqcGFzamNubXdvcmozcTJ3cnVxcDlmb3c4ZXVyeTg5MjM2NDYzNDI1NDc2MjN0ZGlrdWFzeWRhN2lmeWhhdWlza2hmYWxramZ2c2xranZsa2NmeG5sa2pjeGZkdm5mZGxranZuZGxrZmpudmRsa2ZqZ25kbGtmamduc2Rsb2l2bnpvaWx4bnZrbGl4bmd2ZGxvc3lucmpnZmxzaWpmbmxhc2RrdmhubGthdXNkaGZnbDtrYXN1aGY7bGthc3VpZmhlcmxpO2t1d2VocmZsaXV3ZWtyZmhsYXNka3J1aGZsa2FzdW52Zi5rdWZhc2RuYmd2bGthdXNkZ2hmbGFramZzZ2k7b2FzdWRoZztXT1NJR0pIJztTSWhkZ2FkO2ZsaXZqbmFzO2xpZ2pzO09JTEdIJ1dPU0lFSEcnd1NPSUpGR0w7U0RLRko7U0xLREpGJ1NQT0lmdWRqZydwd1NVSUVPSlRGRydQV1NJRU9KRidwU09FSkYnUEFFRlNPSidTRkVPSidTUE9GSic7c09ERkpMU0RLRkpMS0RTSkZMREtTRkpMREtGSkdLSkZER0hLRkpHSEtGSkdIS0psa3NqZmxrZGZqc2xrZGZqc2xka2Zqc2xrZGpmbGtzZGZqbHNrZGZqa2pidnNpdXdlZ2Jud2V1aW9od29laWpwYXNqY25td29yajNxMndydXFwOWZvdzhldXJ5ODkyMzY0NjM0MjU0NzYyM3RkaWt1YXN5ZGE3aWZ5aGF1aXNraGZhbGtqZnZzbGtqdmxrY2Z4bmxramN4ZmR2bmZkbGtqdm5kbGtmam52ZGxrZmpnbmRsa2ZqZ25zZGxvaXZuem9pbHhudmtsaXhuZ3ZkbG9zeW5yamdmbHNpamZubGFzZGt2aG5sa2F1c2RoZmdsO2thc3VoZjtsa2FzdWlmaGVybGk7a3V3ZWhyZmxpdXdla3JmaGxhc2RrcnVoZmxrYXN1bnZmLmt1ZmFzZG5iZ3Zsa2F1c2RnaGZsYWtqZnNnaTtvYXN1ZGhnO1dPU0lHSkgnO1NJaGRnYWQ7ZmxpdmpuYXM7bGlnanM7T0lMR0gnV09TSUVIRyd3U09JSkZHTDtTREtGSjtTTEtESkYnU1BPSWZ1ZGpnJ3B3U1VJRU9KVEZHJ1BXU0lFT0pGJ3BTT0VKRidQQUVGU09KJ1NGRU9KJ1NQT0ZKJztzT0RGSkxTREtGSkxLRFNKRkxES1NGSkxES0ZKR0tKRkRHSEtGSkdIS0ZKR0hLSmxrc2pmbGtkZmpzbGtkZmpzbGRrZmpzbGtkamZsa3NkZmpsc2tkZmpramJ2c2l1d2VnYm53ZXVpb2h3b2VpanBhc2pjbm13b3JqM3Eyd3J1cXA5Zm93OGV1cnk4OTIzNjQ2MzQyNTQ3NjIzdGRpa3Vhc3lkYTdpZnloYXVpc2toZmFsa2pmdnNsa2p2bGtjZnhubGtqY3hmZHZuZmRsa2p2bmRsa2ZqbnZkbGtmamduZGxrZmpnbnNkbG9pdm56b2lseG52a2xpeG5ndmRsb3N5bnJqZ2Zsc2lqZm5sYXNka3ZobmxrYXVzZGhmZ2w7a2FzdWhmO2xrYXN1aWZoZXJsaTtrdXdlaHJmbGl1d2VrcmZobGFzZGtydWhmbGthc3VudmYua3VmYXNkbmJndmxrYXVzZGdoZmxha2pmc2dpO29hc3VkaGc7V09TSUdKSCc7U0loZGdhZDtmbGl2am5hcztsaWdqcztPSUxHSCdXT1NJRUhHJ3dTT0lKRkdMO1NES0ZKO1NMS0RKRidTUE9JZnVkamcncHdTVUlFT0pURkcnUFdTSUVPSkYncFNPRUpGJ1BBRUZTT0onU0ZFT0onU1BPRkonO3NPREZKTFNES0ZKTEtEU0pGTERLU0ZKTERLRkpHS0pGREdIS0ZKR0hLRkpHSEtKbGtzamZsa2RmanNsa2RmanNsZGtmanNsa2RqZmxrc2Rmamxza2RmamtqYnZzaXV3ZWdibndldWlvaHdvZWlqcGFzamNubXdvcmozcTJ3cnVxcDlmb3c4ZXVyeTg5MjM2NDYzNDI1NDc2MjN0ZGlrdWFzeWRhN2lmeWhhdWlza2hmYWxrag==",
        "YXNsaWRqYWtzbGpmaGRsa3NqZGZubGtzZHZqbmxrZGp4dm5sa3hmZGp2bg==",
        "MDk0NzgyNTk4MDM1NDc5ODM0NzUwOTMyNDg1LTkwMzQyODUwMzk0ODUgZiBka2hqZ2ZkayB1Z2ggMzQ5N3Y3bmcwMzU4MzA0OTgwOXY1",
        "MDk0NzgyNTk4MDM1NDc5ODM0NzUwOTMyNDg1LTkwMzQyODUwMzk0ODUgZiBka2hqZ2ZkayB1Z2ggMzQ5N3Y3bmcwMzU4MzA0OTgwOXY1LV8rKyswPS0wOS0wODk5OHl1ZmR1c25iZGF2ZmNsa2pzZG4vLi8/LnMucWEnd2VwZG9xM1sw"
    };

    for(uint i = 0 ; i < 6 ; i++)
    {
        if(encodeInBase64(std::vector<unsigned char>(strs[i].begin(),strs[i].end())) != strsEncoded[i])
            return false;

        std::vector<unsigned char> decodedStr = decodeFromBase64(strsEncoded[i]);

        if(strs[i] != std::string(decodedStr.begin(),decodedStr.end()))
            return false;
    }

    return true;
}

bool test_base64Decoding()
{
    /* Known value to compare against */
    std::string str = "sALDCFHNSAODFHn;oasVNDJP[O}{][asdf[as[fpdkasefionjmasolfnioalsindlas;D";

    std::string strBase64 = "c0FMRENGSE5TQU9ERkhuO29hc1ZOREpQW099e11bYXNkZlthc1tmcGRrYXNlZmlvbmptYXNvbGZuaW9hbHNpbmRsYXM7RA==";   
    std::vector<unsigned char> decodedStr = decodeFromBase64(strBase64);
    
    return str == std::string(decodedStr.begin(),decodedStr.end());
}

bool test_base64Encoding()
{
    /* Known value to compare against */
    std::string strBase64 = "c0FMRENGSE5TQU9ERkhuO29hc1ZOREpQW09MQUlWU05EUFs7V0pQQVNPRkRLSltQQU9GU0RLSnBdQU9TSkRLT0pBT1M7SkQnO09BU0pEJ1twb0FMU0lKRkQnTFNJRkRKbmw7YXNkZmtqO2xhc2tkamJuZnY7YWtsc2pkdmJuO2Fsa3NkanZuYjthbGtzZGp2Ym47bGtzZGFqdmJuO2Fza2xkanZiO2Fza2RqdmJhcztrZGpmYnZuO2FzbGtkamZobidsO3NBREtGSEphU0FTYWZxYXdyM3dlcTU0cjMyNDUzNGZ3ZTMyNzQ1NjI3NmdyMjNnIGM4dDQzNzgydHI4MnRjcmIgZTg3OTM4N3Jxd2dkdXl2YXN1ZGcyMzk3OHlyZXQyMTM5OHJ0ZTg3Z2ZjaXdlZ2Y5d2VxaGY=";
    
    std::string str = "sALDCFHNSAODFHn;oasVNDJP[OLAIVSNDP[;WJPASOFDKJ[PAOFSDKJp]AOSJDKOJAOS;JD';OASJD'[poALSIJFD'LSIFDJnl;asdfkj;laskdjbnfv;aklsjdvbn;alksdjvnb;alksdjvbn;lksdajvbn;askldjvb;askdjvbas;kdjfbvn;aslkdjfhn'l;sADKFHJaSASafqawr3weq54r324534fwe327456276gr23g c8t43782tr82tcrb e879387rqwgduyvasudg23978yret21398rte87gfciwegf9weqhf";    
    
    std::string encodedString = encodeInBase64(std::vector<unsigned char>(str.begin(),str.end()));

    return strBase64 == encodedString;
}

bool test_randomStringLength()
{
    const int maxStrLen = 10000;

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(1,maxStrLen);

    const int strLen = distribution(generator);
    
    std::string randomString = generateRandomString(strLen);

    return randomString.size() == strLen;
}

bool test_padStringRandom()
{
    const int maxStrLen = 10000;

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(0,maxStrLen);

    const int strLen = distribution(generator);
    const int nOfBytes = distribution(generator);

    std::string testString = "";

    for(int i = 0; i < strLen; i++)
    {
        testString += "1";
    }

    std::string argString = testString; 

    if(nOfBytes < strLen)
    {
        testString =  testString.substr(0,nOfBytes);
    }
    else if(nOfBytes > strLen)
    {
        int diffElems =  nOfBytes - strLen;

        for(int i = 0; i < diffElems ; i++)
        {
            testString += 'A';
        }
    }

    return testString == padString(argString,nOfBytes,'A');
}

bool test_padString()
{
    std::string testString = "hello111111111111111111111111111";
    return testString == padString("hello",32,'1');
}

int main (int argc, char* argv[])
{
    if(!test_padString())
        return -1;

    if(!test_padStringRandom())
        return -1;

    if(!test_randomStringLength())
        return -1;

    if(!test_base64Encoding())
        return -1;

    if(!test_base64Decoding())
        return -1;

    if(!test_randomLengthBase64Encoding())
        return -1;

    if(!test_KnownConversions())
        return -1;

    return 0;
}