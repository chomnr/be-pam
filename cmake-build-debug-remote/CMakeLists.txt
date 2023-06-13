cmake_minimum_required(VERSION 3.25)
project(be_pam C)

set(CMAKE_C_STANDARD 11)

include_directories(/usr/include/security)

add_library(be_pam SHARED library.c)
