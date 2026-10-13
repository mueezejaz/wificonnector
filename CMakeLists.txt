cmake_minimum_required(VERSION 3.16)
project(edurm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Shared core used by BOTH front-ends.
add_library(edurm_core STATIC
  src/util.cpp
  src/wlan.cpp
  src/profile.cpp
  src/eduroam.cpp
  src/diag.cpp
)

# WIN32_LEAN_AND_MEAN is deliberately NOT defined: it hides <objbase.h>, which is
# where StringFromGUID2 (used by guidToString) is declared, and wlan.cpp then
# fails with "identifier not found".
target_compile_definitions(edurm_core PUBLIC
  UNICODE _UNICODE
  NOMINMAX            # windows.h otherwise defines min()/max() as macros
  _CRT_SECURE_NO_WARNINGS
  WINVER=0x0A00 _WIN32_WINNT=0x0A00
)

target_compile_options(edurm_core PUBLIC /W4 /utf-8)

target_link_libraries(edurm_core PUBLIC
  wlanapi    # Native Wifi API
  ole32      # StringFromGUID2
  crypt32    # certificate store enumeration
  bcrypt     # CryptHashCertificate2 (--pin-sha256)
  advapi32   # registry (legacy TLS), certificate stores
)

# ------------------------------------------------------------------ CLI -----
add_executable(edurm
  src/main.cpp
)
target_link_libraries(edurm PRIVATE edurm_core)

# ------------------------------------------------------------------ GUI -----
add_executable(edurm-gui WIN32
  src/gui/main_gui.cpp
)
target_link_libraries(edurm-gui PRIVATE
  edurm_core
  user32 gdi32 comctl32 dwmapi uxtheme
)