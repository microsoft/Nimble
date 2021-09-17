# Add the HACL* Verified Cryptographic Libraries
add_subdirectory(NimbleEverCrypt)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT endorser_t.h endorser_t.c endorser_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/endorser.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/endorser.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(enclave ecalls.cpp endorser.cpp
                       ${CMAKE_CURRENT_BINARY_DIR}/endorser_t.c)
target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
  openenclave::oelibcxx nimble_evercrypt)
