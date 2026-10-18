@rem Copyright (c) 2026 CyNickal Software LLC
@rem SPDX-License-Identifier: MIT

@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=%DMA_DEPLOY_DIR%"
if "%TARGET%"=="" (
  echo usage: deploy_to_target.bat DEST
  echo    or set DMA_DEPLOY_DIR to the copy share, for example \\server\poc
  exit /b 1
)

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

cmake --preset Release
if errorlevel 1 exit /b 1
cmake --build --preset Release --target dma_hello
if errorlevel 1 exit /b 1

if not exist "%TARGET%\bin" mkdir "%TARGET%\bin"
if not exist "%TARGET%\hello_dll" mkdir "%TARGET%\hello_dll"

call :copy_one "bin\dma_hello.exe" "bin\dma_hello.exe"
if errorlevel 1 exit /b 1
call :copy_one "bin\dma_hello.pdb" "bin\dma_hello.pdb"
if errorlevel 1 exit /b 1
rem The process is started from the parent of bin, and that directory's vmm.dll is the one that loads.
call :copy_one "bin\vmm.dll" "vmm.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\leechcore.dll" "leechcore.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\leechcore_driver.dll" "leechcore_driver.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\FTD3XX.dll" "FTD3XX.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\FTD3XXWU.dll" "FTD3XXWU.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\dbghelp.dll" "dbghelp.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\symsrv.dll" "symsrv.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\symsrv.yes" "symsrv.yes"
if errorlevel 1 exit /b 1
call :copy_one "bin\hello_dll.dll" "hello_dll\hello_dll.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\hello_dll.pdb" "hello_dll\hello_dll.pdb"
if errorlevel 1 exit /b 1
call :copy_one "bin\beep_dll.dll" "hello_dll\beep_dll.dll"
if errorlevel 1 exit /b 1
call :copy_one "bin\beep_dll.pdb" "hello_dll\beep_dll.pdb"
if errorlevel 1 exit /b 1

rem A vmm.dll left inside bin loads first and then ignores the symbol DLLs above it.
del /q "%TARGET%\bin\vmm.dll" "%TARGET%\bin\leechcore.dll" "%TARGET%\bin\leechcore_driver.dll" "%TARGET%\bin\FTD3XX.dll" "%TARGET%\bin\FTD3XXWU.dll" "%TARGET%\bin\dbghelp.dll" "%TARGET%\bin\symsrv.dll" "%TARGET%\bin\symsrv.yes" 2>nul

echo.
echo Copied to %TARGET%
echo Run these from that directory:
echo   bin\dma_hello.exe --hello --device fpga://
echo   bin\dma_hello.exe --ark --beep --device fpga://
exit /b 0

:copy_one
if not exist "%ROOT%%~1" (
  echo missing build output: %~1
  exit /b 1
)
copy /Y "%ROOT%%~1" "%TARGET%\%~2" >nul
if errorlevel 1 exit /b 1
echo (ok) %~2
exit /b 0
