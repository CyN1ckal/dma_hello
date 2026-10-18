@rem Copyright (c) 2026 CyNickal Software LLC
@rem SPDX-License-Identifier: MIT

@echo off
REM Build with the Debug CMake preset, then run the DMA injector.

echo ============================================================
echo DMA Injection PoC - Full Run
echo ============================================================

cd /d "%~dp0"
call build.bat
if errorlevel 1 (
    echo.
    echo ============================================================
    echo BUILD FAILED!
    echo ============================================================
    if "%1"=="wait" pause
    exit /b 1
)

echo.
echo Running DMA inject for notepad...
echo.

bin\dma_hello.exe --process notepad.exe --dll hello_dll\hello_dll.dll --device fpga://

echo.
echo ============================================================
echo Notepad PoC Complete!
echo ============================================================
echo.
echo Check notepad.exe for the "Hello from DMA!" popup.
echo.

if "%1"=="wait" pause
