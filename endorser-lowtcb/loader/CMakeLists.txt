set(LOADER_SOURCE
    ${CMAKE_SOURCE_DIR}/loader/loader.cpp
    ${CMAKE_SOURCE_DIR}/loader/utilities/enclave_hash.cpp
    ${CMAKE_SOURCE_DIR}/loader/utilities/enclave_sigstruct.cpp
)

include_directories(
    ${CMAKE_SOURCE_DIR}/loader
    ${CMAKE_SOURCE_DIR}/loader/include
    ${CMAKE_SOURCE_DIR}/loader/utilities
    ${CMAKE_SOURCE_DIR}/include
)

add_library(loader_lib STATIC ${LOADER_SOURCE})
