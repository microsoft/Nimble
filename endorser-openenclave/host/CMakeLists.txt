add_custom_command(
  OUTPUT endorser_u.h endorser_u.c endorser_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/endorser.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/endorser.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(endorser_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/endorser_u.c)

target_include_directories(
  endorser_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR})


target_link_libraries(endorser_host openenclave::oehost)