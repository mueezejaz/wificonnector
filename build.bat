@echo off
REM Builds edurm with the MSVC toolchain without requiring CMake.
REM Finds the newest Visual Studio / Build Tools install automatically.

setlocal

where cl.exe >nul 2>&1
if %errorlevel%==0 goto :build

set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
  echo [error] Visual Studio not found. Install "Desktop development with C++"
  echo         from the Visual Studio Build Tools, then re-run this script.
  exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VCINSTALL=%%i
if "%VCINSTALL%"=="" (
  echo [error] Could not locate an MSVC toolchain via vswhere.
  exit /b 1
)

if exist "%VCINSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
  call "%VCINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
) else (
  call "%VCINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
)

:build
if %errorlevel% neq 0 (
  echo [error] vcvars failed with exit code %errorlevel%.
  exit /b 1
)

where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
  echo [error] cl.exe is still not on PATH after vcvars.
  exit /b 1
)

if not exist build mkdir build

REM /EHsc     : C++ exception handling
REM /std:c++17: language standard
REM /W4       : high warnings
REM /utf-8    : source and execution charset are UTF-8
REM /DUNICODE /D_UNICODE : UTF-16 Win32 entry points
REM NOMINMAX is required: windows.h otherwise defines min()/max() as macros,
REM which breaks std::min/std::max in the GUI.
cl /nologo /EHsc /std:c++17 /W4 /utf-8 /O2 /MT ^
   /DNOMINMAX /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
   /Fe:build\edurm.exe /Fo:build\ ^
   src\main.cpp src\util.cpp src\wlan.cpp src\profile.cpp src\eduroam.cpp ^
   /link wlanapi.lib ole32.lib crypt32.lib advapi32.lib

if errorlevel 1 (
  echo.
  echo [FAIL] CLI build failed
  exit /b 1
)

echo.
echo [OK] built build\edurm.exe

REM ---------------------------------------------------------------- GUI -----
echo.
echo Building GUI (edurm-gui.exe) ...

REM The GUI object files get their own directory so they never clash with the
REM CLI objects in build\.
if not exist build\gui mkdir build\gui

cl /nologo /EHsc /std:c++17 /W4 /utf-8 /O2 /MT ^
   /DNOMINMAX /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
   /Fe:build\edurm-gui.exe /Fo:build\gui\ ^
   src\gui\main_gui.cpp src\util.cpp src\wlan.cpp src\profile.cpp src\eduroam.cpp ^
   /link /SUBSYSTEM:WINDOWS ^
         wlanapi.lib ole32.lib crypt32.lib advapi32.lib ^
         user32.lib gdi32.lib comctl32.lib dwmapi.lib uxtheme.lib

if errorlevel 1 (
  echo.
  echo [FAIL] GUI build failed
  exit /b 1
)

echo [OK] built build\edurm-gui.exe
endlocal