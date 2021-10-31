cmake_minimum_required(VERSION 3.8)

# https://cmake.org/cmake/help/latest/prop_tgt/CXX_STANDARD.html
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# expected behaviour
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++lastest")

project(HMAC)

set(SRCDIR "../src/")

# add your .cpp files here
add_executable(test.out ../tests/test.cpp ../src/hmac/functional/hmac.cpp)

# add include directory
target_include_directories(test.out PUBLIC ../src/hmac/functional)

target_link_libraries(test.out)
