cmake_minimum_required(VERSION 3.16)
project(edurm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(edurm
  src/main.cpp
  src/util.cpp
  src/wlan.cpp
  src/profile.cpp
)

target_compile_definitions(edurm PRIVATE
  UNICODE _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX            # windows.h otherwise defines min()/max() as macros
  _CRT_SECURE_NO_WARNINGS
)

target_compile_options(edurm PRIVATE /W4 /utf-8)

target_link_libraries(edurm PRIVATE
  wlanapi    # Native Wifi API
  ole32      # StringFromGUID2
  crypt32    # certificate store enumeration
  advapi32
)