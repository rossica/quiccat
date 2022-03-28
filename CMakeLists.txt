# CMakeList.txt : CMake project for quiccat, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("quiccat")

# Add source to this project's executable.
add_executable (quiccat "quiccat.cpp" "quiccat.h")

# TODO: Add tests and install targets if needed.
