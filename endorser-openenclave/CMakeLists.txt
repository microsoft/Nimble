cmake_minimum_required(VERSION 3.11)

project("NimbleLedger Endorser" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    openssl
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/endorser.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/endorser.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS endorser_host sign
    COMMAND endorser_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS endorser_host sign testfile
  COMMAND endorser_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave-sgx2
  DEPENDS enclave
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:enclave> $<TARGET_FILE:enclave>-sgx2
)

add_custom_command(
  OUTPUT enclave/enclave-sgx2.signed
  DEPENDS enclave enclave/endorser-sgx2.conf private.pem enclave/enclave-sgx2
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave>-sgx2 -c
          ${CMAKE_SOURCE_DIR}/enclave/endorser-sgx2.conf -k private.pem)

add_custom_target(sign2 ALL DEPENDS enclave/enclave-sgx2.signed)
