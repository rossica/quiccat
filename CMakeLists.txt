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

# Add source to this project's executable.
add_executable (quiccat "quiccat.cpp" "quiccat.h" "auth.cpp" "auth.h" "platform.h")
target_link_libraries(quiccat msquic_static base_link OpenSSLQuic)
target_compile_features(quiccat PRIVATE cxx_std_20)

if (WIN32)
    target_compile_options(quiccat PRIVATE /sdl /GF /Gy /WX /W4 /Zi /Zf
        $<$<CONFIG:RELEASE>:/O1 /Zo>)
    target_link_options(quiccat PUBLIC /DEBUG:FULL /WX
        $<$<CONFIG:RELEASE>:/INCREMENTAL:NO /OPT:REF>)
else()
    target_compile_options(quiccat PRIVATE -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits
        -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers
        $<$<CONFIG:DEBUG>:-g -Og>)
endif()
