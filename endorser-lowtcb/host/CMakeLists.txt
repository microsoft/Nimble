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
    ${PROTO_DIR}/endorser.proto
    DEPENDS ${PROTO_DIR}/endorser.proto
)

link_directories(${protobuf_BINARY_DIR}/lib)

add_library(proto STATIC
    ${CMAKE_SOURCE_DIR}/host/endorser.pb.cc
    ${CMAKE_SOURCE_DIR}/host/endorser.pb.h
    ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.cc
    ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.h
)
target_link_libraries(proto PUBLIC grpc++ grpc++_reflection)

enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)
set(CAN_USE_ASSEMBLER TRUE)
set(ASM_SOURCE_FILES ${CMAKE_SOURCE_DIR}/host/enclu.asm)

add_executable(endorser_host
               host.cpp
               ${CMAKE_SOURCE_DIR}/host/endorser.pb.cc
               ${CMAKE_SOURCE_DIR}/host/endorser.grpc.pb.cc
               ${ASM_SOURCE_FILES})

target_include_directories(
  endorser_host
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(endorser_host grpc++ loader_lib sgx_dcap_ql)
