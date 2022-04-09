# CMakeList.txt : CMake project for quiccat, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.17)

project ("quiccat")

set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
set(QUIC_BUILD_TOOLS OFF CACHE BOOL "Don't use the tools")
set(QUIC_BUILD_TEST OFF CACHE BOOL "Don't need the tests")
set(QUIC_BUILD_PERF OFF CACHE BOOL "Don't need perf")
set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
set(QUIC_BUILD_SHARED OFF CACHE BOOL "Statically linking")
set(CMAKE_BUILD_TYPE "Debug")
add_subdirectory(submodules/msquic)
target_compile_features(inc INTERFACE cxx_std_20)

# Add source to this project's executable.
add_executable (quiccat "quiccat.cpp" "quiccat.h")
target_link_libraries(quiccat base_link msquic OpenSSLQuic)
target_compile_features(quiccat PRIVATE cxx_std_20)