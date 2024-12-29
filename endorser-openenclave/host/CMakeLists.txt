include(FetchContent)
FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc
    GIT_TAG        v1.37.0
)
set(FETCHCONTENT_QUIET OFF)
FetchContent_MakeAvailable(gRPC)
message(STATUS "Using gRPC ${gRPC_VERSION}")

# Protobuf
# compile endorser.proto
set(PROTO_DIR "${CMAKE_SOURCE_DIR}/proto")
message(STATUS "Using PROTO_DIR at ${PROTO_DIR}")
message(STATUS "Using Protobuf at ${protobuf_BINARY_DIR}")
message(STATUS "Using gRPC CPP Plugin at ${grpc_BINARY_DIR}")

add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/host/endorser.pb.cc
           ${CMAKE_SOURCE_DIR}/host/endorser.pb.h
           ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.cc
           ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.h
    COMMAND ${protobuf_BINARY_DIR}/protoc
    ARGS --grpc_out "${CMAKE_SOURCE_DIR}/host/"
         --cpp_out "${CMAKE_SOURCE_DIR}/host/"
         -I "${PROTO_DIR}"
         --plugin=protoc-gen-grpc=${grpc_BINARY_DIR}/grpc_cpp_plugin
    endorser.proto
)

link_directories(${protobuf_BINARY_DIR}/lib)

add_library(proto STATIC
    ${CMAKE_SOURCE_DIR}/host/endorser.pb.cc
    ${CMAKE_SOURCE_DIR}/host/endorser.pb.h
    ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.cc
    ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.h
)
target_link_libraries(proto PUBLIC grpc++ grpc++_reflection)

add_custom_command(
  OUTPUT endorser_u.h endorser_u.c endorser_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/endorser.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/endorser.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(endorser_host
               host.cpp
               ${CMAKE_SOURCE_DIR}/host/endorser.pb.cc
               ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/endorser_u.c)

target_include_directories(
  endorser_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR})


target_link_libraries(endorser_host openenclave::oehost grpc++)
