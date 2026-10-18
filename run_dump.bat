@rem Copyright (c) 2026 CyNickal Software LLC
@rem SPDX-License-Identifier: MIT

@echo off
setlocal

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

echo === hello_dll exports ===
dumpbin /EXPORTS "%~dp0bin\hello_dll.dll"
echo === beep_dll exports ===
dumpbin /EXPORTS "%~dp0bin\beep_dll.dll"
exit /b 0
