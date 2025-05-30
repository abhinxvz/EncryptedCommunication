include_directories (${PROJECT_SOURCE_DIR}/include)

add_executable (Test_AES256EncryptorHandler Test_AES256EncryptorHandler.cpp)
target_link_libraries (Test_AES256EncryptorHandler ec)

add_executable (Test_RSAEncryptorHandler Test_RSAEncryptorHandler.cpp)
target_link_libraries (Test_RSAEncryptorHandler ec)

add_executable (Test_SHA256HashHandler Test_SHA256HashHandler.cpp)
target_link_libraries (Test_SHA256HashHandler ec)

add_executable(Test_Utils Test_Utils.cpp)
target_link_libraries(Test_Utils ec)