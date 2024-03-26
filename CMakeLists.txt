cmake_minimum_required(VERSION 3.10)

project(SimpleDNS LANGUAGES C)

# Specify the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

add_executable(simpledns main.c)

include(GNUInstallDirs)
install(TARGETS simpledns RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
