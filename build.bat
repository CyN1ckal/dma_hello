@rem Copyright (c) 2026 CyNickal Software LLC
@rem SPDX-License-Identifier: MIT

@echo off
setlocal

set "ROOT=%~dp0"
cd /d "%ROOT%"

set "VCVARSALL="
for %%P in (
  "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsall.bat"
  "C:\Program Files\Microsoft Visual Studio\2026\Insiders\VC\Auxiliary\Build\vcvarsall.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
) do (
  if exist %%P (
    set "VCVARSALL=%%~P"
    goto :found_vs
  )
)

echo Visual Studio vcvarsall.bat not found.
exit /b 1

:found_vs
call "%VCVARSALL%" amd64
if errorlevel 1 exit /b 1

cmake --preset Debug
if errorlevel 1 exit /b 1
cmake --build --preset Debug
if errorlevel 1 exit /b 1

echo.
echo === tests ===
bin\dma_hello_tests.exe "~[system]"
if errorlevel 1 exit /b 1

echo.
echo Build OK
echo   bin\dma_hello.exe
echo   bin\dma_hello_tests.exe
echo   hello_dll\hello_dll.dll
echo   hello_dll\beep_dll.dll
echo Run these from the repository root:
echo   bin\dma_hello.exe --hello --device fpga://
echo   bin\dma_hello.exe --ark --beep --device fpga://
exit /b 0
