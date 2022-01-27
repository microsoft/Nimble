cmake_minimum_required(VERSION 3.11)

project("NimbleLedger Endorser" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(loader)
add_subdirectory(host)

