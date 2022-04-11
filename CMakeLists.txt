# CMakeList.txt : CMake project for quiccat, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.17)

project ("quiccat")

set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
set(QUIC_BUILD_SHARED OFF CACHE BOOL "Statically linking")
add_subdirectory(submodules/msquic)
target_compile_features(inc INTERFACE cxx_std_20)

if (WIN32)
    add_compile_options(/WX /W4 /sdl)
else()
    add_compile_options(-Werror -Wall -Wextra -Wformat=2 -Wno-type-limits
        -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers)
endif()

# Add source to this project's executable.
add_executable (quiccat "quiccat.cpp" "quiccat.h" "auth.cpp" "auth.h")
target_link_libraries(quiccat base_link msquic OpenSSLQuic)
target_compile_features(quiccat PRIVATE cxx_std_20)