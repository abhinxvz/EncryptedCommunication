cmake_minimum_required(VERSION 3.16)

project(EncryptedCommunication)

find_package(OpenSSL REQUIRED)

find_package(Doxygen)

if(DOXYGEN_FOUND)
    
    set(DOXYGEN_IN  ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    add_custom_target( 
        doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating documentation with Doxygen"
    )

else(DOXYGEN_FOUND)

    message("Doxygen not found, cannot generate documentation")

endif()

add_library(ec)

target_include_directories(
    ec
    
    PRIVATE ${PROJECT_SOURCE_DIR}/include
    
    PRIVATE ${PROJECT_SOURCE_DIR}/src
)

target_sources(
    ec
    
    PUBLIC ${PROJECT_SOURCE_DIR}/include/AES256EncryptorHandler.hpp
    PUBLIC ${PROJECT_SOURCE_DIR}/include/RSAEncryptorHandler.hpp
    PUBLIC ${PROJECT_SOURCE_DIR}/include/SHAHashHandler.hpp

    PRIVATE ${PROJECT_SOURCE_DIR}/include/CryptoHandler.hpp
    PRIVATE ${PROJECT_SOURCE_DIR}/include/HashHandler.hpp

    PRIVATE ${PROJECT_SOURCE_DIR}/include/Utils.hpp

    PRIVATE ${PROJECT_SOURCE_DIR}/src/AES256EncryptorHandler.cpp
    PRIVATE ${PROJECT_SOURCE_DIR}/src/RSAEncryptorHandler.cpp
    PRIVATE ${PROJECT_SOURCE_DIR}/src/SHAHashHandler.cpp
    PRIVATE ${PROJECT_SOURCE_DIR}/src/Utils.cpp
)

target_link_libraries(ec OpenSSL::SSL)

add_subdirectory(${PROJECT_SOURCE_DIR}/test)

enable_testing()

add_test(NAME Test_AES256EncryptorHandler COMMAND Test_AES256EncryptorHandler)

add_test(NAME Test_RSAEncryptorHandler COMMAND Test_RSAEncryptorHandler)

add_test(NAME Test_SHA256HashHandler COMMAND Test_SHA256HashHandler)

add_test(NAME Test_Utils COMMAND Test_Utils)